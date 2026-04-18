package mdns

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServiceEntry represents a discovered mDNS service instance.
type ServiceEntry struct {
	// Name is the fully qualified domain name (FQDN) of the service instance.
	// Format: "<Instance>.<Type>.<Domain>."
	// e.g. "My Web Server._http._tcp.local."
	Name string

	// Instance is the user-friendly name of the service instance.
	// e.g. "My Web Server"
	Instance string

	// Type is the service type in the format "_application._protocol".
	// e.g. "_http._tcp"
	Type string

	// Domain is the DNS domain for the service.
	// e.g. "local"
	Domain string

	// Host is the hostname of the device providing the service.
	// e.g. "macbook.local."
	Host string

	// Port is the port number on which the service is available.
	Port uint16

	// IPAddrs contains the IP addresses of the host.
	// Including both IPv4 and IPv6.
	IPAddrs []net.IPAddr

	// Text contains the TXT record key-value pairs.
	Text map[string]string

	// TTL is the time-to-live in seconds from the original resource record.
	TTL uint32

	// Expiry is the expiration time calculated from TTL.
	Expiry time.Time
}

// typeFQDN returns the service type FQDN in the format "<Type>.<Domain>.".
func (se *ServiceEntry) typeFQDN() string {
	if len(se.Domain) == 0 {
		return fmt.Sprintf("%s.", se.Type)
	}

	return fmt.Sprintf("%s.%s.", se.Type, se.Domain)
}

// InterfaceFilter is a function type that filters network interfaces.
// It returns true if the interface should be used, false otherwise.
type InterfaceFilter func(iface net.Interface) bool

// Question defines the parameters for an mDNS query request.
type Question struct {
	// Instance name (optional, used for specific instance query).
	// e.g. "My Web Server"
	Instance string

	// Service type.
	// e.g. "_http._tcp"
	Type string

	// Domain name.
	// Default to "local" if empty.
	Domain string

	// Record type to query (PTR, SRV, TXT, etc.).
	// Default to TypePTR if 0.
	Record RecordType
}

// TypeEnumQuestion is a convenient predefined question for service type enumeration.
// It queries for "_services._dns-sd._udp.local." to discover all available service types.
var TypeEnumQuestion = Question{
	Type:   "_services._dns-sd._udp",
	Domain: "local",
	Record: TypePTR,
}

// ensureDefaults applies default values to zero fields.
func (q *Question) ensureDefaults() {
	if q.Domain == "" {
		q.Domain = "local"
	}
	if q.Record == 0 {
		q.Record = TypePTR
	}
}

// fqdn returns a normalized FQDN from the Question fields.
// Format: <Instance>.<Type>.<Domain>.
//
// It enforces length limits defined in RFC6763 Section 7.2.
//
// Returns `ErrFQDNLen` if the resulting FQDN exceeds 255 bytes.
// Returns `ErrDomainRequired` if the domain is empty.
func (q *Question) fqdn() (string, error) {
	b := strings.Builder{}

	instance := strings.Trim(q.Instance, ".")
	if len(instance) > 0 {
		b.WriteString(instance)
		b.WriteByte('.')
	}

	svcType := strings.Trim(q.Type, ".")
	if len(svcType) > 0 {
		b.WriteString(svcType)
		b.WriteByte('.')
	}

	domain := strings.Trim(q.Domain, ".")
	if len(domain) == 0 {
		return "", ErrDomainRequired
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

// querier performs mDNS service discovery queries.
type querier struct {
	// network specifies which IP protocols to use (IPv4, IPv6, or both).
	network NetworkStack

	// ifaceFilter filters which network interfaces to use.
	ifaceFilter InterfaceFilter

	// multicastResp indicates whether multicast responses are expected.
	// If false, the QU bit is set to request unicast responses.
	multicastResp bool

	// Enable continuous monitoring.
	// If enabled, multicastResp MUST be enabled (RFC6762 Section 5.2).
	continuous bool

	// conns holds the active multicast UDP connections.
	conns []*multicastConn

	// knownEntries caches discovered services for Known-Answer Suppression.
	// Key format: "<Instance>.<Type>.<Domain>."
	//
	// TODO: Improve cache management (e.g., periodic cleanup of expired entries).
	knownEntries map[string]ServiceEntry
}

// newQuerier creates a new querier with default settings.
func newQuerier() *querier {
	return &querier{
		network:      IPv4,
		knownEntries: make(map[string]ServiceEntry),
	}
}

// QueryOption configures a querier instance.
type QueryOption func(q *querier)

// QueryWithNetwork sets the IP protocol stack to use.
func QueryWithNetwork(network NetworkStack) QueryOption {
	return func(q *querier) {
		q.network = network
	}
}

// QueryWithInterfaceFilter sets a filter function to select network interfaces.
func QueryWithInterfaceFilter(filter InterfaceFilter) QueryOption {
	return func(q *querier) {
		q.ifaceFilter = filter
	}
}

// QueryWithMulticastResponse enables or disables multicast responses.
//
// If false, the QU bit is set to request unicast responses.
func QueryWithMulticastResponse(enable bool) QueryOption {
	return func(q *querier) {
		q.multicastResp = enable
	}
}

// QueryWithContinuous enables or disables continuous querying mode.
//
// If enabled, multicast responses are forcibly enabled (RFC6762 Section 5.2).
func QueryWithContinuous(enable bool) QueryOption {
	return func(q *querier) {
		q.continuous = enable
	}
}

// Query performs an mDNS query and returns a channel of discovered services.
//
// The query runs asynchronously. Results are streamed to the returned channel
// as they are received. The channel is closed when the query completes,
// the context is canceled, or an error occurs.
//
// For continuous queries, the channel remains open and receives updates
// until the context is canceled.
func Query(ctx context.Context, questions []Question, options ...QueryOption) (<-chan *ServiceEntry, error) {
	q := newQuerier()

	for _, opt := range options {
		opt(q)
	}

	// Continuous query mode inherently requires multicast responses.
	if q.continuous {
		q.multicastResp = true
	}

	msg, err := q.makeQueryMessage(questions)
	if err != nil {
		return nil, err
	}

	err = q.setupConnections()
	if err != nil {
		return nil, err
	}

	ch := make(chan *ServiceEntry)

	// Clean up connections and close channel when context is done.
	go func() {
		<-ctx.Done()
		q.closeConnections()
		close(ch)
	}()

	// Start a listener for each network interface.
	for _, conn := range q.conns {
		go q.readPump(ctx, conn, ch)
	}

	if msg != nil {
		if q.continuous {
			// Continuous mode: repeat query with exponential backoff (RFC6762 Section 5.2).
			go q.continuousQuery(ctx, msg)
		} else {
			// One-shot mode: send a single query.
			q.sendQuery(msg)
		}
	}

	return ch, nil
}

// makeQueryMessage constructs an mDNS query message from the given questions.
//
// If multicast responses are not required, the QU bit is set and a random
// Transaction ID is generated.
func (q *querier) makeQueryMessage(questions []Question) (*dnsmessage.Message, error) {
	if len(questions) == 0 {
		return nil, nil
	}

	msg := &dnsmessage.Message{}
	for _, question := range questions {
		question.ensureDefaults()

		name, err := question.fqdn()
		if err != nil {
			return nil, err
		}

		mq := dnsmessage.Question{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.Type(question.Record),
			Class: dnsmessage.ClassINET,
		}

		// Set Unicast-Response bit (bit 15) if multicast response is not required.
		// This requests that responders reply via unicast.
		if !q.multicastResp {
			mq.Class |= 1 << 15
		}

		msg.Questions = append(msg.Questions, mq)
	}

	// For unicast queries, use a random Transaction ID.
	if !q.multicastResp {
		msg.Header.ID = uint16(rand.IntN(math.MaxUint16))
	}

	return msg, nil
}

// setupConnections creates and binds multicast UDP connections on eligible interfaces.
func (q *querier) setupConnections() error {
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

		if q.ifaceFilter != nil && !q.ifaceFilter(iface) {
			continue
		}

		// Create separate connections for IPv4 and IPv6 based on the stack preference.
		if q.network.Has(IPv4) {
			conn, err = createConn(&iface, IPv4, q.multicastResp)
			if err == nil {
				q.conns = append(q.conns, conn)
			}
		}
		if q.network.Has(IPv6) {
			conn, err = createConn(&iface, IPv6, q.multicastResp)
			if err == nil {
				q.conns = append(q.conns, conn)
			}
		}
	}

	if len(q.conns) == 0 {
		return ErrNoEligibleIface
	}

	return nil
}

// dnsMessageToServiceEntries extracts ServiceEntry objects from a DNS message.
// It aggregates records from both the Answer and Additional sections.
//
// The iface and src parameters are used to populate Zone information for IP addresses.
func dnsMessageToServiceEntries(msg *dnsmessage.Message, iface *net.Interface, src *net.UDPAddr) []*ServiceEntry {
	entries := map[string]*ServiceEntry{}

	// Helper to get or create a ServiceEntry by name.
	existOrCreateEntry := func(name string) *ServiceEntry {
		if e, ok := entries[name]; ok {
			return e
		}
		e := &ServiceEntry{
			Name: name,
		}
		entries[name] = e

		return e
	}
	now := time.Now()
	// Track the shortest TTL received for an instance (records may have different TTLs).
	updateExpiry := func(e *ServiceEntry, ttl uint32) {
		expiry := now.Add(time.Second * time.Duration(ttl)).Truncate(time.Second)
		if e.Expiry.After(expiry) || e.Expiry.IsZero() {
			e.Expiry = expiry
			e.TTL = ttl
		}
	}

	// ipAddrs maps hostname -> resolved IP addresses (both IPv4 and IPv6).
	ipAddrs := map[string][]net.IPAddr{}
	updateIPAddrs := func(host string, ipAddr net.IPAddr) {
		ipAddrs[host] = append(ipAddrs[host], ipAddr)
	}

	// Process both Answers and Additionals.
	for _, r := range append(msg.Answers, msg.Additionals...) {
		header := r.Header
		switch body := r.Body.(type) {
		case *dnsmessage.PTRResource:
			entry := existOrCreateEntry(body.PTR.String())

			// Extract Type and Domain from the PTR name.
			// e.g., "_http._tcp.local." -> Type="_http._tcp", Domain="local"
			svcType := strings.TrimSuffix(header.Name.String(), ".")
			if idx := strings.LastIndex(svcType, "."); idx > 0 {
				entry.Type, entry.Domain = svcType[:idx], svcType[idx+1:]
			} else {
				// Fallback: unable to split, store as-is
				entry.Type = svcType
			}
			updateExpiry(entry, header.TTL)

		case *dnsmessage.SRVResource:
			entry := existOrCreateEntry(header.Name.String())
			entry.Host = body.Target.String()
			entry.Port = body.Port
			updateExpiry(entry, header.TTL)

		case *dnsmessage.TXTResource:
			entry := existOrCreateEntry(header.Name.String())
			entry.Text = textToMap(body.TXT)
			updateExpiry(entry, header.TTL)

		case *dnsmessage.AResource:
			addr := net.IPAddr{IP: net.IP(body.A[:])}
			if iface != nil {
				addr.Zone = iface.Name
			}
			updateIPAddrs(header.Name.String(), addr)

		case *dnsmessage.AAAAResource:
			addr := net.IPAddr{IP: net.IP(body.AAAA[:])}
			if src != nil {
				addr.Zone = src.Zone
			}
			updateIPAddrs(header.Name.String(), addr)
		}
	}

	// Assemble final ServiceEntry slice.
	entrySlice := make([]*ServiceEntry, 0, len(entries))
	for _, entry := range entries {
		// Map discovered IP addresses to the entry.
		entry.IPAddrs = ipAddrs[entry.Host]

		// Strip service suffix to extract the clean instance name.
		// e.g., "MyPrinter._http._tcp.local." -> "MyPrinter"
		if instance, ok := strings.CutSuffix(entry.Name, "."+entry.typeFQDN()); ok {
			entry.Instance = instance
		}

		entrySlice = append(entrySlice, entry)
	}

	return entrySlice
}

// readPump continuously reads from the multicast connection and pushes parsed
// entries to the channel.
func (q *querier) readPump(ctx context.Context, conn *multicastConn, ch chan<- *ServiceEntry) {
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

		// mDNS responses must have OpCode 0, QR=1, and AA=1.
		if msg.OpCode != 0 || !msg.Response || !msg.Authoritative {
			continue
		}

		// TC (Truncated) bit is not supported. Truncated messages are silently ignored.
		if msg.Truncated {
			continue
		}

		entries := dnsMessageToServiceEntries(msg, p.iface, p.src)
		if len(entries) == 0 {
			continue
		}

		for _, entry := range entries {
			if q.continuous {
				// Cache entry for Known-Answer Suppression in continuous mode.
				// TODO: Implement periodic cache cleanup.
				q.knownEntries[entry.Name] = *entry
			}

			select {
			case <-ctx.Done():
				return
			case ch <- entry:
			}
		}
	}
}

// sendQuery sends a single mDNS query packet on all active connections.
func (q *querier) sendQuery(msg *dnsmessage.Message) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}

	for _, conn := range q.conns {
		conn.Write(b)
	}

	return nil
}

// continuousQuery handles repeated querying with exponential backoff
// (RFC6762 Section 5.2).
//
// It populates Known Answers to suppress redundant multicast traffic.
func (q *querier) continuousQuery(ctx context.Context, msg *dnsmessage.Message) {
	interval := 1 * time.Second
	maxInterval := 1 * time.Hour

	for {
		// Populate known answers to suppress redundant multicast traffic.
		msg.Answers = q.makeKnownAnswers()
		q.sendQuery(msg)

		select {
		case <-ctx.Done():
			return

		case <-time.After(interval):
			// Exponential backoff: double interval until max limit.
			interval *= 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
}

// makeKnownAnswers builds the Answer section for Known-Answer Suppression.
// It includes PTR records for cached services that still have significant TTL remaining.
// RFC6762 Section 7.1: Answers should only be included if their TTL is > 50%.
//
// TODO: Expand to include SRV, TXT, and address records.
func (q *querier) makeKnownAnswers() []dnsmessage.Resource {
	var rs []dnsmessage.Resource

	now := time.Now()
	for _, e := range q.knownEntries {
		ttl := int(e.Expiry.Sub(now).Seconds())
		// Only include records with > 50% TTL remaining to avoid stale answers.
		if ttl < int(e.TTL/2) {
			continue
		}
		r := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(e.typeFQDN()),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
				TTL:   uint32(ttl),
			},
			Body: &dnsmessage.PTRResource{
				PTR: dnsmessage.MustNewName(e.Name),
			},
		}
		rs = append(rs, r)
	}

	return rs
}

// closeConnections closes all active multicast connections.
func (q *querier) closeConnections() {
	for _, c := range q.conns {
		c.Close()
	}
}
