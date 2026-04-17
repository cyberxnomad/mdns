package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cyberxnomad/mdns"
)

type httpSvcAttrs struct {
	port uint16
}

// Hostname implements [mdns.AttrsProvider].
func (h *httpSvcAttrs) Hostname() string {
	host, _ := os.Hostname()
	return host
}

// Port implements [mdns.AttrsProvider].
func (h *httpSvcAttrs) Port() uint16 {
	return h.port
}

// IPAddrs implements [mdns.AttrsProvider].
func (h *httpSvcAttrs) IPAddrs() []net.IPAddr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	ipaddrs := make([]net.IPAddr, 0, len(addrs))

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4 := ipnet.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() {
			ipaddrs = append(ipaddrs, net.IPAddr{IP: ipv4})
		} else if ipv6 := ipnet.IP.To16(); ipv6 != nil && ipv6.IsLinkLocalUnicast() {
			ipaddrs = append(ipaddrs, net.IPAddr{IP: ipv6})
		}
	}

	return ipaddrs
}

// Text implements [mdns.AttrsProvider].
func (h *httpSvcAttrs) Text() map[string]string {
	text := make(map[string]string)
	text["api"] = "v1"
	text["status"] = "passing"

	return text
}

var _ mdns.AttrsProvider = (*httpSvcAttrs)(nil)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	responder := mdns.NewResponder()

	err := responder.Serve()
	if err != nil {
		panic(err)
	}

	service := mdns.Service{
		Instance: "My Web Server",
		Type:     "_http._tcp",
	}

	err = responder.Register(service, &httpSvcAttrs{port: 80})
	if err != nil {
		panic(err)
	}

	<-sigChan
	responder.Shutdown()
}
