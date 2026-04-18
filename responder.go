package mdns

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const typeEnumFQDN = "_services._dns-sd._udp.local."

// Service represents a service to be advertised via mDNS.
type Service struct {
	// Instance is the user-friendly name of the service instance.
	// e.g., "My Web Server"
	Instance string

	// Type is the service type in the format "_application._protocol".
	// e.g., "_http._tcp"
	Type string

	// Domain is the DNS domain for the service.
	// Default to "local" if empty.
	Domain string

	// TTL is the time-to-live for advertised records in seconds.
	// Default to 120 if 0.
	TTL uint32
}

// ensureDefaults applies default values to zero fields.
func (s *Service) ensureDefaults() {
	if s.Domain == "" {
		s.Domain = "local"
	}

	if s.TTL == 0 {
		s.TTL = 120
	}
}

// fqdn returns the fully qualified domain name of the service instance.
//
// Format: <Instance>.<Type>.<Domain>.
//
// Returns ErrFQDNLen if the resulting FQDN exceeds 255 bytes.
func (s *Service) fqdn() (string, error) {
	b := strings.Builder{}

	instance := strings.Trim(s.Instance, ".")
	if len(instance) > 0 {
		b.WriteString(instance)
		b.WriteByte('.')
	}

	svcType := strings.Trim(s.Type, ".")
	if len(svcType) > 0 {
		b.WriteString(svcType)
		b.WriteByte('.')
	}

	domain := strings.Trim(s.Domain, ".")
	if len(domain) == 0 {
		domain = "local"
	}
	b.WriteString(domain)
	b.WriteByte('.')

	fqdn := b.String()
	// Total length of a FQDN is limited to 255 bytes.
	if len(fqdn) > 255 {
		return "", ErrFQDNLen
	}

	return fqdn, nil
}

// typeFQDN returns the service type FQDN in the format "<Type>.<Domain>.".
func (s *Service) typeFQDN() string {
	return fmt.Sprintf("%s.%s.", s.Type, s.Domain)
}

// serviceState manages the lifecycle and runtime data of a registered service.
type serviceState struct {
	Service
	attrs AttrsProvider
}

// hostFQDN returns the fully qualified domain name of the service's host.
// Format: "<hostname>.<Domain>.".
// Returns empty string if the hostname is not set.
func (ss *serviceState) hostFQDN() string {
	hostname := ss.attrs.Hostname()
	if hostname == "" {
		return ""
	}

	return fmt.Sprintf("%s.%s.", hostname, ss.Domain)
}

// buildProbeMessage constructs a DNS query used for conflict detection.
// It queries for any records matching the service's FQDN to verify uniqueness.
// The QU bit is set to request an immediate unicast response (RFC 6762 Section 8.1).
func (ss *serviceState) buildProbeMessage() ([]byte, error) {
	fqdn, err := ss.fqdn()
	if err != nil {
		return nil, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()

	// Question: ANY query for the FQDN with QU bit set.
	b.StartQuestions()
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(fqdn),
		Type:  dnsmessage.TypeALL,
		Class: dnsmessage.ClassINET | (1 << 15), // QU. RFC6762 Section 8.1.
	})

	// Authority: Proposed records for tiebreaking during simultaneous probes.
	b.StartAuthorities()
	if srv := ss.makeSRVResource(); srv != nil {
		// Cache-flush bit is intentionally NOT set on probe records.
		srv.Header.Class &= 0x7FFF
		b.SRVResource(srv.Header, *srv.Body.(*dnsmessage.SRVResource))
	}

	if txt := ss.makeTXTResource(); txt != nil {
		// Cache-flush bit is intentionally NOT set on probe records.
		txt.Header.Class &= 0x7FFF
		b.TXTResource(txt.Header, *txt.Body.(*dnsmessage.TXTResource))
	}

	return b.Finish()
}

// buildAnnounceOrGoodbyeMessage builds a DNS response for service announcement or withdrawal.
// If isAnnounce is true, records use the service's configured TTL.
// If false, records use TTL=0 to signal service removal (Goodbye, RFC6762 Section 10.1).
func (ss *serviceState) buildAnnounceOrGoodbyeMessage(isAnnounce bool) ([]byte, error) {
	ttl := ss.TTL
	if !isAnnounce {
		ttl = 0
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		Response:      true, // QR bit = 1
		Authoritative: true, // AA bit = 1
	})
	b.EnableCompression()

	b.StartAnswers()
	if ptr := ss.makePTRResource(); ptr != nil {
		ptr.Header.TTL = ttl
		b.PTRResource(ptr.Header, *ptr.Body.(*dnsmessage.PTRResource))
	}

	b.StartAdditionals()
	additionals := ss.collectAdditionalRecords()
	for _, r := range additionals {
		r.Header.TTL = ttl
		switch body := r.Body.(type) {
		case *dnsmessage.SRVResource:
			b.SRVResource(r.Header, *body)

		case *dnsmessage.TXTResource:
			b.TXTResource(r.Header, *body)

		case *dnsmessage.AResource:
			b.AResource(r.Header, *body)

		case *dnsmessage.AAAAResource:
			b.AAAAResource(r.Header, *body)
		}
	}

	return b.Finish()
}

func (ss *serviceState) makePTRResource() *dnsmessage.Resource {
	fqdn, _ := ss.fqdn()

	return &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(ss.typeFQDN()),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET, // No cache-flush bit
			TTL:   ss.TTL,
		},
		Body: &dnsmessage.PTRResource{
			PTR: dnsmessage.MustNewName(fqdn),
		},
	}
}

func (ss *serviceState) makeSRVResource() *dnsmessage.Resource {
	fqdn, _ := ss.fqdn()
	hostFQDN := ss.hostFQDN()
	port := ss.attrs.Port()

	if hostFQDN == "" || port == 0 {
		return nil
	}

	return &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(fqdn),
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET | (1 << 15), // Cache-flush
			TTL:   ss.TTL,
		},
		Body: &dnsmessage.SRVResource{
			Target: dnsmessage.MustNewName(hostFQDN),
			Port:   port,
		},
	}
}

func (ss *serviceState) makeTXTResource() *dnsmessage.Resource {
	fqdn, _ := ss.fqdn()
	text := ss.attrs.Text()
	if len(text) == 0 {
		return nil
	}

	return &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(fqdn),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET | (1 << 15), // Cache-flush
			TTL:   ss.TTL,
		},
		Body: &dnsmessage.TXTResource{
			TXT: textToSlice(text),
		},
	}
}

func (ss *serviceState) makeAResources() []*dnsmessage.Resource {
	hostFQDN := ss.hostFQDN()
	addrs := ss.attrs.IPAddrs()

	if hostFQDN == "" || len(addrs) == 0 {
		return nil
	}

	var records []*dnsmessage.Resource
	header := dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName(hostFQDN),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET | (1 << 15), // Cache-flush
		TTL:   ss.TTL,
	}

	for _, addr := range addrs {
		if ip := addr.IP.To4(); ip != nil {
			records = append(records, &dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AResource{A: [4]byte(ip)},
			})
		}
	}

	return records
}

func (ss *serviceState) makeAAAAResources() []*dnsmessage.Resource {
	hostFQDN := ss.hostFQDN()
	addrs := ss.attrs.IPAddrs()

	if hostFQDN == "" || len(addrs) == 0 {
		return nil
	}

	var records []*dnsmessage.Resource
	header := dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName(hostFQDN),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET | (1 << 15), // Cache-flush
		TTL:   ss.TTL,
	}

	for _, addr := range addrs {
		// Skip IPv4-mapped IPv6 addresses (they are already covered by A records).
		if addr.IP.To4() != nil {
			continue
		}
		if ip := addr.IP.To16(); ip != nil {
			records = append(records, &dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AAAAResource{AAAA: [16]byte(ip)},
			})
		}
	}

	return records
}

func (ss *serviceState) collectAllRecords(qtype dnsmessage.Type) []*dnsmessage.Resource {
	var records []*dnsmessage.Resource

	switch qtype {
	case dnsmessage.TypePTR:
		records = appendNonNil(records, ss.makePTRResource())
		records = appendNonNil(records, ss.collectAdditionalRecords()...)

	case dnsmessage.TypeSRV:
		records = appendNonNil(records, ss.makeSRVResource())

	case dnsmessage.TypeTXT:
		records = appendNonNil(records, ss.makeTXTResource())

	case dnsmessage.TypeA:
		records = appendNonNil(records, ss.makeAResources()...)

	case dnsmessage.TypeAAAA:
		records = appendNonNil(records, ss.makeAAAAResources()...)

	case dnsmessage.TypeALL:
		records = appendNonNil(records, ss.makePTRResource())
		records = appendNonNil(records, ss.collectAdditionalRecords()...)
	}

	return records
}

func (ss *serviceState) collectAdditionalRecords() []*dnsmessage.Resource {
	var records []*dnsmessage.Resource
	records = appendNonNil(records, ss.makeSRVResource())
	records = appendNonNil(records, ss.makeTXTResource())
	records = appendNonNil(records, ss.makeAResources()...)
	records = appendNonNil(records, ss.makeAAAAResources()...)
	return records
}

// Responder is an mDNS responder that advertises services and answers queries.
type Responder struct {
	mutex sync.RWMutex

	// services maps instance FQDN to its state.
	// Key format: "<Instance>.<Type>.<Domain>."
	services map[string]*serviceState

	// types maps service type FQDN to all instances of that type.
	// Key format: "<Type>.<Domain>."
	types map[string][]*serviceState

	// hostnames maps host FQDN to services that claim that hostname.
	// Key format: "<Hostname>.<Domain>."
	hostnames map[string][]*serviceState

	// probing tracks ongoing probes.
	//Key format: "<Instance>.<Type>.<Domain>.", value is a channel closed on conflict.
	probing map[string]chan struct{}

	// announceStop tracks stop channels for ongoing announcement goroutines.
	// Key format: "<Instance>.<Type>.<Domain>."
	announceStop map[string]chan struct{}

	// conns holds the multicast UDP connections.
	conns []*multicastConn

	// running indicates whether the responder is running.
	running atomic.Bool
	ctx     context.Context
	cancel  context.CancelFunc

	// Configuration options (set via ResponderOption).
	ifaceFilter     InterfaceFilter
	network         NetworkStack
	probeWaitTime   time.Duration
	probeRetryCount int
	announceCount   int
}

// ResponderOption configures a Responder instance.
type ResponderOption func(*Responder)

// ResponderWithInterfaceFilter sets a filter function to select which network interfaces to use.
// Only interfaces for which the filter returns true will be used.
func ResponderWithInterfaceFilter(filter InterfaceFilter) ResponderOption {
	return func(r *Responder) {
		r.ifaceFilter = filter
	}
}

// ResponderWithNetwork sets the IP protocol stack to use (IPv4, IPv6, or both).
func ResponderWithNetwork(network NetworkStack) ResponderOption {
	return func(r *Responder) {
		r.network = network
	}
}

// ResponderWithProbeWaitTime sets the time to wait between probe packets.
// Default is 250ms (RFC6762 Section 8.1).
func ResponderWithProbeWaitTime(waitTime time.Duration) ResponderOption {
	return func(r *Responder) {
		r.probeWaitTime = waitTime
	}
}

// ResponderWithProbeRetryCount sets the number of probe packets to send.
// Default is 3.
func ResponderWithProbeRetryCount(count int) ResponderOption {
	return func(r *Responder) {
		r.probeRetryCount = count
	}
}

// ResponderWithAnnounceCount sets the number of announcement packets to send.
// The value is clamped between 2 and 8 per RFC6762 Section 8.3.
func ResponderWithAnnounceCount(count int) ResponderOption {
	return func(r *Responder) {
		if count < 2 {
			count = 2
		}
		if count > 8 {
			count = 8
		}
		r.announceCount = count
	}
}

// NewResponder creates a new mDNS Responder with the given options.
func NewResponder(options ...ResponderOption) *Responder {
	r := &Responder{
		services:        make(map[string]*serviceState),
		types:           make(map[string][]*serviceState),
		hostnames:       make(map[string][]*serviceState),
		probing:         make(map[string]chan struct{}),
		announceStop:    make(map[string]chan struct{}),
		network:         IPv4,
		probeWaitTime:   250 * time.Millisecond,
		probeRetryCount: 3,
		announceCount:   2, // RFC6762 recommends 2-8 announcements
	}

	for _, opt := range options {
		opt(r)
	}

	return r
}

// AttrsProvider supplies runtime attributes for a registered service.
// These values may change over time and are queried when constructing responses.
type AttrsProvider interface {
	// Hostname returns the local hostname (without the ".local" suffix).
	Hostname() string

	// Port returns the service port number.
	Port() uint16

	// IPAddrs returns the IP addresses of the host.
	IPAddrs() []net.IPAddr

	// Text returns the TXT record key-value pairs.
	Text() map[string]string
}

func (r *Responder) getService(fqdn string) *serviceState {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	fqdn = strings.ToLower(fqdn)

	return r.services[fqdn]
}

func (r *Responder) getServicesByType(typeFQDN string) []*serviceState {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	typeFQDN = strings.ToLower(typeFQDN)

	return r.types[typeFQDN]
}

// getServicesByHostFQDN returns all services associated with the given host FQDN.
// The hostFQDN should be in the format "<hostname>.<Domain>." (case-insensitive).
func (r *Responder) getServicesByHostFQDN(hostFQDN string) []*serviceState {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	hostFQDN = strings.ToLower(hostFQDN)

	return r.hostnames[hostFQDN]
}

// addService adds a service to the responder's internal maps.
func (r *Responder) addService(fqdn string, state *serviceState) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fqdn = strings.ToLower(fqdn)

	r.services[fqdn] = state

	typ := strings.ToLower(state.typeFQDN())
	r.types[typ] = append(r.types[typ], state)

	if hostFQDN := state.hostFQDN(); hostFQDN != "" {
		key := strings.ToLower(hostFQDN)
		r.hostnames[key] = append(r.hostnames[key], state)
	}
}

// removeService removes a service from the responder's internal maps.
func (r *Responder) removeService(fqdn string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fqdn = strings.ToLower(fqdn)

	state, ok := r.services[fqdn]
	if !ok {
		return
	}

	delete(r.services, fqdn)

	typ := strings.ToLower(state.typeFQDN())

	states := r.types[typ]
	r.types[typ] = slices.DeleteFunc(states, func(s *serviceState) bool {
		return s == state
	})
	if len(r.types[typ]) == 0 {
		delete(r.types, typ)
	}

	// Remove from hostnames
	if hostFQDN := state.hostFQDN(); hostFQDN != "" {
		key := strings.ToLower(hostFQDN)
		hostStates := r.hostnames[key]
		r.hostnames[key] = slices.DeleteFunc(hostStates, func(s *serviceState) bool {
			return s == state
		})
		if len(r.hostnames[key]) == 0 {
			delete(r.hostnames, key)
		}
	}
}

// Register adds a service to be advertised via mDNS.
// It performs conflict probing before announcing the service.
//
// Returns `ErrResponderNotServed` if the Responder is not running.
// Returns `ErrServiceRegistered` if the service is already registered.
// Returns `ErrServiceConflict` if a name conflict is detected during probing.
func (r *Responder) Register(svc Service, provider AttrsProvider) error {
	if !r.running.Load() {
		return ErrResponderNotServed
	}

	svc.ensureDefaults()

	fqdn, err := svc.fqdn()
	if err != nil {
		return err
	}

	fqdn = strings.ToLower(fqdn)

	existed := r.getService(fqdn)
	if existed != nil {
		return ErrServiceRegistered
	}

	state := &serviceState{Service: svc, attrs: provider}

	// Probe for conflicts (RFC6762 Section 8.1).
	err = r.probe(state)
	if err != nil {
		return err
	}

	r.addService(fqdn, state)

	// Announce the service with exponential backoff (RFC6762 Section 8.3).
	announceStop := make(chan struct{})

	r.mutex.Lock()
	if old, exists := r.announceStop[fqdn]; exists {
		close(old)
	}
	r.announceStop[fqdn] = announceStop
	r.mutex.Unlock()

	go func() {
		defer r.cancelAnnounce(fqdn)
		r.announceWithBackoff(state, announceStop)
	}()

	return nil
}

// cancelAnnounce stops and removes the announcement for the given FQDN.
// It returns true if an active announcement was canceled, false otherwise.
func (r *Responder) cancelAnnounce(fqdn string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fqdn = strings.ToLower(fqdn)

	ch, ok := r.announceStop[fqdn]
	if ok {
		close(ch)
		delete(r.announceStop, fqdn)
	}

	return ok
}

// Unregister stops advertising a service and sends a Goodbye announcement.
//
// Returns `ErrResponderNotServed` if the Responder is not running.
// Returns `ErrServiceNotFound` if the service is not registered.
func (r *Responder) Unregister(svc Service) error {
	if !r.running.Load() {
		return ErrResponderNotServed
	}

	svc.ensureDefaults()

	fqdn, err := svc.fqdn()
	if err != nil {
		return err
	}

	fqdn = strings.ToLower(fqdn)

	state := r.getService(fqdn)
	if state == nil {
		return ErrServiceNotFound
	}

	r.cancelAnnounce(fqdn)

	// Send Goodbye (RFC6762 Section 10.1).
	r.goodbye(state)

	r.removeService(fqdn)

	return nil
}

// Update refreshes the runtime attributes of a registered service.
//
// It stops any ongoing announcements, updates the service's attributes and TTL,
// and restarts the announcement process if the service was actively announcing.
// If the service had finished announcing, a single announcement is sent.
//
// Note: The service identity (Instance, Type, Domain) cannot be changed.
// To change the identity, Unregister the old service and Register a new one.
//
// Returns `ErrResponderNotServed` if the Responder is not running.
// Returns `ErrServiceNotFound` if the service is not registered.
func (r *Responder) Update(svc Service, provider AttrsProvider) error {
	if !r.running.Load() {
		return ErrResponderNotServed
	}

	svc.ensureDefaults()

	fqdn, err := svc.fqdn()
	if err != nil {
		return err
	}

	fqdn = strings.ToLower(fqdn)

	state := r.getService(fqdn)
	if state == nil {
		return ErrServiceNotFound
	}

	// Stop any ongoing announcements and check if it was active.
	announcing := r.cancelAnnounce(fqdn)

	providerHostFQDN := func(s Service, provider AttrsProvider) string {
		hostname := provider.Hostname()
		if hostname == "" {
			return ""
		}

		return fmt.Sprintf("%s.%s.", hostname, s.Domain)
	}

	// Update both the runtime attributes and TTL.
	r.mutex.Lock()
	oldHostFQDN := strings.ToLower(state.hostFQDN())
	newHostFQDN := strings.ToLower(providerHostFQDN(state.Service, provider))

	// Update hostnames map if hostname changed
	if oldHostFQDN != newHostFQDN {
		if oldHostFQDN != "" {
			hostStates := r.hostnames[oldHostFQDN]
			r.hostnames[oldHostFQDN] = slices.DeleteFunc(hostStates, func(s *serviceState) bool {
				return s == state
			})
			if len(r.hostnames[oldHostFQDN]) == 0 {
				delete(r.hostnames, oldHostFQDN)
			}
		}
		if newHostFQDN != "" {
			r.hostnames[newHostFQDN] = append(r.hostnames[newHostFQDN], state)
		}
	}

	state.attrs = provider
	state.TTL = svc.TTL
	r.mutex.Unlock()

	// Restart announcement with exponential backoff if it was active,
	// otherwise send a single announcement to notify the change.
	if announcing {
		announceStop := make(chan struct{})

		r.mutex.Lock()
		r.announceStop[fqdn] = announceStop
		r.mutex.Unlock()

		go func() {
			defer r.cancelAnnounce(fqdn)
			r.announceWithBackoff(state, announceStop)
		}()
	} else {
		r.announceOnce(state)
	}

	return nil
}

// Serve starts the mDNS responder, binding to network interfaces and listening for queries.
//
// Returns `ErrResponderServed` if the responder is already running.
func (r *Responder) Serve() error {
	if !r.running.CompareAndSwap(false, true) {
		return ErrResponderServed
	}

	err := r.setupConnections()
	if err != nil {
		r.running.Store(false)
		return err
	}

	r.ctx, r.cancel = context.WithCancel(context.Background())

	// Start a listener for each network interface.
	for _, conn := range r.conns {
		go r.readPump(conn)
	}

	return nil
}

// Shutdown stops the mDNS responder, sends Goodbye packets for all services,
// and closes all network connections.
//
// Returns `ErrResponderNotServed` if the responder is not running.
func (r *Responder) Shutdown() error {
	if !r.running.CompareAndSwap(true, false) {
		return ErrResponderNotServed
	}

	r.cancel()

	// Send Goodbye for all registered services.
	r.mutex.Lock()
	services := make([]*serviceState, 0, len(r.services))
	for _, svc := range r.services {
		services = append(services, svc)
	}
	r.mutex.Unlock()

	for _, svc := range services {
		r.goodbye(svc)
	}

	r.closeConnections()

	// Reset state to allow reuse.
	r.mutex.Lock()
	r.ctx = nil
	r.cancel = nil
	r.services = make(map[string]*serviceState)
	r.types = make(map[string][]*serviceState)
	r.hostnames = make(map[string][]*serviceState)
	r.probing = make(map[string]chan struct{})
	r.announceStop = make(map[string]chan struct{})
	r.mutex.Unlock()

	return nil
}

// setupConnections creates and binds multicast UDP connections on eligible interfaces.
func (r *Responder) setupConnections() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	var conn *multicastConn

	for _, iface := range ifaces {
		// Only use interfaces that are up
		//
		// Note: net.FlagMulticast is intentionally ignored because some virtual
		// interfaces (e.g., WireGuard) may not set this flag even though they
		// can transmit multicast traffic.
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if r.ifaceFilter != nil && !r.ifaceFilter(iface) {
			continue
		}

		// Create separate connections for IPv4 and IPv6 based on the stack preference.
		if r.network.Has(IPv4) {
			conn, err = createConn(&iface, IPv4, true)
			if err == nil {
				r.conns = append(r.conns, conn)
			}
		}
		if r.network.Has(IPv6) {
			conn, err = createConn(&iface, IPv6, true)
			if err == nil {
				r.conns = append(r.conns, conn)
			}
		}
	}

	if len(r.conns) == 0 {
		return ErrNoEligibleIface
	}

	return nil
}

// conflictDetect checks if a received ServiceEntry conflicts with an ongoing probe.
// It sends a signal to the probe's conflict channel if a conflict is detected.
//
// TODO: Implement full simultaneous probe tiebreaking (RFC6762 Section 8.2).
func (r *Responder) conflictDetect(entry *ServiceEntry) bool {
	r.mutex.RLock()
	conflict := r.probing[entry.Name]
	r.mutex.RUnlock()

	if conflict == nil {
		return false
	}

	// TODO: Compare SRV and TXT records for tiebreaking.

	select {
	case <-r.ctx.Done():
		return false
	case conflict <- struct{}{}:
		return true
	default:
		return false
	}
}

// handleResponse processes incoming mDNS response messages for conflict detection.
func (r *Responder) handleResponse(msg *dnsmessage.Message) {
	if !msg.Response {
		return
	}

	entries := dnsMessageToServiceEntries(msg, nil, nil)

	conflictDone := false
	for _, entry := range entries {
		if !conflictDone {
			conflictDone = r.conflictDetect(entry)
		}
	}
}

// handleQuery processes incoming mDNS query messages and sends appropriate responses.
func (r *Responder) handleQuery(msg *dnsmessage.Message, conn *multicastConn, src *net.UDPAddr) {
	if msg.Response || len(msg.Questions) == 0 {
		return
	}

	var candidates []*dnsmessage.Resource
	for _, q := range msg.Questions {
		candidates = append(candidates, r.collectRecordsForQuestion(q)...)
	}

	if len(candidates) == 0 {
		return
	}

	// Deduplicate before building response to avoid redundant records.
	records := dedupResources(candidates)

	r.sendQueryResponse(msg, records, conn, src)
}

// sendQueryResponse builds and sends a DNS response for the given records.
//
// Note: RFC6762 Section 6 forbids including questions in mDNS responses.
func (r *Responder) sendQueryResponse(query *dnsmessage.Message, records []*dnsmessage.Resource, conn *multicastConn, src *net.UDPAddr) {
	answers, additionals := partitionResources(records, query.Questions)
	if len(answers) == 0 && len(additionals) == 0 {
		return
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            query.ID,
		Response:      true,
		Authoritative: true,
	})
	b.EnableCompression()

	// RFC6762 Section 6:
	// Multicast DNS responses MUST NOT contain any questions in the
	// Question Section.

	buildResources := func(b *dnsmessage.Builder, rs []*dnsmessage.Resource) {
		for _, r := range rs {
			switch body := r.Body.(type) {
			case *dnsmessage.PTRResource:
				b.PTRResource(r.Header, *body)

			case *dnsmessage.SRVResource:
				b.SRVResource(r.Header, *body)

			case *dnsmessage.TXTResource:
				b.TXTResource(r.Header, *body)

			case *dnsmessage.AResource:
				b.AResource(r.Header, *body)

			case *dnsmessage.AAAAResource:
				b.AAAAResource(r.Header, *body)
			}
		}
	}

	b.StartAnswers()
	buildResources(&b, answers)

	b.StartAdditionals()
	buildResources(&b, additionals)

	buf, err := b.Finish()
	if err != nil {
		return
	}

	// Send via multicast or unicast based on QU bit in the first question.
	if query.Questions[0].Class&(1<<15) == 0 {
		conn.Write(buf)
	} else {
		conn.WriteTo(buf, src)
	}
}

// collectRecordsForQuestion returns all DNS records that answer the given question.
func (r *Responder) collectRecordsForQuestion(q dnsmessage.Question) []*dnsmessage.Resource {
	name := q.Name.String()

	// Service type enumeration
	if strings.EqualFold(name, typeEnumFQDN) {
		return r.makeEnumResources()
	}

	// Service discovery: PTR query for a service type (e.g., "_http._tcp.local.").
	if services := r.getServicesByType(name); len(services) > 0 {
		var records []*dnsmessage.Resource
		for _, ss := range services {
			records = appendNonNil(records, ss.collectAllRecords(q.Type)...)
		}
		return records
	}

	// Specific instance query (e.g., "MyPrinter._http._tcp.local.").
	if ss := r.getService(name); ss != nil {
		return ss.collectAllRecords(q.Type)
	}

	// Hostname query (e.g., "my-device.local.")
	if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.TypeALL {
		if services := r.getServicesByHostFQDN(name); len(services) > 0 {
			var records []*dnsmessage.Resource
			for _, ss := range services {
				if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
					records = appendNonNil(records, ss.makeAResources()...)
				}
				if q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.TypeALL {
					records = appendNonNil(records, ss.makeAAAAResources()...)
				}
			}
			return records
		}
	}

	return nil
}

// dedupResources removes duplicate DNS resources from the slice.
//
// Records are considered duplicates if they have the same Name, Type, and content.
// For A and AAAA records, the IP address is included in the comparison.
func dedupResources(rs []*dnsmessage.Resource) []*dnsmessage.Resource {
	seen := make(map[string]struct{})
	result := make([]*dnsmessage.Resource, 0, len(rs))

	resourceKey := func(r *dnsmessage.Resource) string {
		name := strings.ToLower(r.Header.Name.String())
		base := fmt.Sprintf("%s-%d", name, r.Header.Type)

		// Include record-specific data in the key to distinguish multiple values.
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			return fmt.Sprintf("%s-%v", base, body.A)
		case *dnsmessage.AAAAResource:
			return fmt.Sprintf("%s-%v", base, body.AAAA)
		case *dnsmessage.PTRResource:
			return fmt.Sprintf("%s-%s", base, body.PTR.String())
		case *dnsmessage.SRVResource:
			return fmt.Sprintf("%s-%s-%d", base, body.Target.String(), body.Port)
		// case *dnsmessage.TXTResource:
		// 	return fmt.Sprintf("%s-%v", base, body.TXT)
		default:
			return base
		}
	}

	for _, r := range rs {
		if r == nil {
			continue
		}
		key := resourceKey(r)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}

	return result
}

// partitionResources splits records into Answers and Additionals based on the questions.
//
// Records that directly answer a question go to Answers; others go to Additionals.
func partitionResources(records []*dnsmessage.Resource, questions []dnsmessage.Question) (answers, additionals []*dnsmessage.Resource) {
	matchesQuestion := func(header dnsmessage.ResourceHeader, questions []dnsmessage.Question) bool {
		for _, q := range questions {
			if strings.EqualFold(header.Name.String(), q.Name.String()) &&
				header.Type == q.Type {
				return true
			}
		}
		return false
	}

	for _, r := range records {
		if matchesQuestion(r.Header, questions) {
			answers = append(answers, r)
		} else {
			additionals = append(additionals, r)
		}
	}
	return
}

// readPump continuously reads from the multicast connection and dispatches messages.
func (r *Responder) readPump(conn *multicastConn) {
	for {
		p, err := conn.Read()
		if err != nil {
			// Socket closed or fatal error.
			return
		}

		msg, err := decodeDNSMessage(p.data)
		if err != nil {
			continue
		}

		// OpCode must be 0 for standard mDNS queries/responses.
		if msg.OpCode != 0 {
			continue
		}

		if msg.Response {
			r.handleResponse(msg)
		} else {
			r.handleQuery(msg, conn, p.src)
		}
	}
}

// probe performs conflict detection for a service before announcing it.
//
// It sends three probe queries (by default) and waits for conflicts.
// See RFC6762 Section 8.1.
func (r *Responder) probe(ss *serviceState) error {
	fqdn, err := ss.fqdn()
	if err != nil {
		return err
	}

	probeMsg, err := ss.buildProbeMessage()
	if err != nil {
		return err
	}

	conflictCh := make(chan struct{}, 1)
	r.mutex.Lock()
	r.probing[fqdn] = conflictCh
	r.mutex.Unlock()
	defer func() {
		close(conflictCh)
		r.mutex.Lock()
		delete(r.probing, fqdn)
		r.mutex.Unlock()
	}()

	// Random delay 0-250ms to avoid synchronized probes (RFC6762 Section 8.1).
	time.Sleep(time.Duration(rand.IntN(250)) * time.Millisecond)

	for range r.probeRetryCount {
		for _, conn := range r.conns {
			conn.Write(probeMsg)
		}

		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-conflictCh:
			return ErrServiceConflict
		case <-time.After(r.probeWaitTime):
		}
	}

	return nil
}

// announceOnce sends a single announcement for the service.
func (r *Responder) announceOnce(ss *serviceState) error {
	b, err := ss.buildAnnounceOrGoodbyeMessage(true)
	if err != nil {
		return err
	}

	for _, conn := range r.conns {
		conn.Write(b)
	}

	return nil
}

// announceWithBackoff sends announcements with exponential backoff.
//
// The first announcement is sent immediately, subsequent announcements wait
// with intervals of 1s, 2s, 4s, etc. (RFC6762 Section 8.3).
//
// It stops when the stop channel is closed or the context is canceled.
func (r *Responder) announceWithBackoff(ss *serviceState, stop <-chan struct{}) error {
	interval := 1 * time.Second
	for i := range r.announceCount {
		err := r.announceOnce(ss)
		if err != nil {
			return err
		}

		// Don't wait after the last announcement.
		if i >= r.announceCount-1 {
			break
		}

		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-stop:
			return nil
		case <-time.After(interval):
			// Exponential backoff
			interval *= 2
		}
	}

	return nil
}

// goodbye sends a Goodbye announcement (TTL=0) for the service.
//
// This informs the network that the service is no longer available (RFC6762 Section 10.1).
func (r *Responder) goodbye(ss *serviceState) error {
	b, err := ss.buildAnnounceOrGoodbyeMessage(false)
	if err != nil {
		return err
	}

	for _, conn := range r.conns {
		conn.Write(b)
	}

	return nil
}

// makeEnumResources returns PTR records enumerating all advertised service types.
//
// This is used to respond to "_services._dns-sd._udp.local." queries,
// allowing clients to discover what service types are available on the network.
func (r *Responder) makeEnumResources() []*dnsmessage.Resource {
	var records []*dnsmessage.Resource

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for key, ss := range r.types {
		records = append(records, &dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(typeEnumFQDN),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
				TTL:   ss[0].TTL, // Perhaps we should use the minimum TTL.
			},
			Body: &dnsmessage.PTRResource{
				PTR: dnsmessage.MustNewName(key),
			},
		})
	}

	return records
}

// closeConnections closes all active multicast connections.
func (r *Responder) closeConnections() {
	for _, c := range r.conns {
		c.Close()
	}
}
