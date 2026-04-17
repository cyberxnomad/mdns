package mdns

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// IPv4 multicast group 224.0.0.251.
	mdnsIPv4Addr = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}
	// IPv6 link-local multicast group ff02::fb.
	mdnsIPv6Addr = &net.UDPAddr{
		IP:   net.ParseIP("ff02::fb"),
		Port: 5353,
	}
)

// Incoming mDNS message with metadata.
type packet struct {
	// Raw UDP payload
	data []byte

	// Source address of the sender
	src *net.UDPAddr

	// Network interface where the packet was received
	iface *net.Interface
}

// Wrapper of packet connection tied to a specific interface.
type multicastConn struct {
	conn    net.PacketConn
	network NetworkStack
	iface   *net.Interface
}

// Send data to the appropriate mDNS multicast group based on the stack.
func (c *multicastConn) Write(b []byte) error {
	var err error

	if c.network == IPv4 {
		_, err = c.conn.WriteTo(b, mdnsIPv4Addr)
	} else {
		_, err = c.conn.WriteTo(b, mdnsIPv6Addr)
	}

	return err
}

func (c *multicastConn) WriteTo(b []byte, addr net.Addr) error {
	var err error

	_, err = c.conn.WriteTo(b, addr)

	return err
}

// Extract a packet from the connection and associates it with the interface.
func (c *multicastConn) Read() (*packet, error) {
	buf := make([]byte, 65536)

	n, src, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	data := make([]byte, n)
	copy(data, buf[:n])

	return &packet{
		data:  data,
		src:   src.(*net.UDPAddr),
		iface: c.iface,
	}, nil
}

// Terminate the underlying network connection.
func (c *multicastConn) Close() error {
	return c.conn.Close()
}

func getIfaceLocalAddrV4(iface *net.Interface, QM bool) *net.UDPAddr {
	// For Multicast Queries (QM), we must bind to 0.0.0.0:5353
	// to receive traffic destined for the multicast group on Linux.
	if QM {
		return &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 5353,
		}
	}

	// For Unicast Queries (QU), we bind to a specific local IP
	// on a random port to receive the direct unicast response.
	var localIP net.IP
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipnet.IP.To4(); ip != nil {
			localIP = ip
			break
		}
	}

	if localIP == nil {
		return nil
	}

	return &net.UDPAddr{
		IP:   localIP,
		Port: 0,
	}
}

func getIfaceLocalAddrV6(iface *net.Interface, QM bool) *net.UDPAddr {
	// For Multicast Queries (QM), bind to [::]:5353.
	if QM {
		return &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 5353,
		}
	}

	// For Unicast Queries (QU), bind to the Link-Local address (fe80::/10).
	var localIP net.IP
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		// mDNS IPv6 relies strictly on Link-Local addresses.
		if ip := ipnet.IP.To16(); ip != nil && ip.IsLinkLocalUnicast() {
			localIP = ip
			break
		}
	}

	if localIP == nil {
		return nil
	}

	return &net.UDPAddr{
		IP:   localIP,
		Port: 0,
	}
}

// Set up the socket and join the multicast group for a specific interface.
func createConn(iface *net.Interface, stack NetworkStack, QM bool) (*multicastConn, error) {
	var (
		network string
		addr    *net.UDPAddr
	)

	if stack == IPv4 {
		network = "udp4"
		addr = getIfaceLocalAddrV4(iface, QM)
	} else {
		network = "udp6"
		addr = getIfaceLocalAddrV6(iface, QM)
	}
	if addr == nil {
		return nil, ErrNoEligibleIface
	}

	nc := net.ListenConfig{}

	// If using port 5353 (QM), we must enable SO_REUSEPORT/SO_REUSEADDR
	// to allow co-existence with other mDNS responders (like Avahi or Bonjour).
	if QM {
		nc.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setReusePort(fd)
			})
		}
	}

	c, err := nc.ListenPacket(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}
	// Ensure connection is closed if setup fails later.
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	// Apply multicast-specific socket options.
	if stack == IPv4 {
		err = setupIPv4Conn(c, iface)
	} else {
		err = setupIPv6Conn(c, iface)
	}
	if err != nil {
		return nil, err
	}

	return &multicastConn{
		conn:    c,
		network: stack,
		iface:   iface,
	}, nil
}

// Configure IPv4 multicast membership and routing.
func setupIPv4Conn(c net.PacketConn, iface *net.Interface) error {
	p := ipv4.NewPacketConn(c)

	// Join the mDNS multicast group on this specific interface.
	err := p.JoinGroup(iface, mdnsIPv4Addr)
	if err != nil {
		return err
	}

	// Force outgoing multicast packets to use this specific interface.
	err = p.SetMulticastInterface(iface)
	if err != nil {
		return err
	}

	// Disable loopback to avoid receiving our own queries.
	err = p.SetMulticastLoopback(false)
	if err != nil {
		return err
	}

	return p.SetMulticastTTL(255)
}

// Configure IPv6 multicast membership and routing.
func setupIPv6Conn(c net.PacketConn, iface *net.Interface) error {
	p := ipv6.NewPacketConn(c)

	// Join the mDNS multicast group on this specific interface.
	err := p.JoinGroup(iface, mdnsIPv6Addr)
	if err != nil {
		return err
	}

	// Force outgoing multicast packets to use this specific interface.
	err = p.SetMulticastInterface(iface)
	if err != nil {
		return err
	}

	// Disable loopback to avoid receiving our own queries.
	err = p.SetMulticastLoopback(false)
	if err != nil {
		return err
	}

	return p.SetHopLimit(255)
}
