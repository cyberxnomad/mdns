package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cyberxnomad/mdns"
)

func IfaceFilter() mdns.InterfaceFilter {
	return func(iface net.Interface) bool {
		hasV4, hasV6 := false, false
		addrs, _ := iface.Addrs()

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil {
				hasV4 = true
			}
			if ip := ipnet.IP.To16(); ip != nil && ip.IsLinkLocalUnicast() {
				hasV6 = true
			}
		}

		return hasV4 && hasV6
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	questions := []mdns.Question{
		{Type: "_http._tcp"},
		{Type: "_ipp._tcp"},
		{Type: "_printer._tcp"},
	}

	ch, err := mdns.Query(ctx, questions,
		mdns.QueryWithNetwork(mdns.IPv4|mdns.IPv6),
		mdns.QueryWithInterfaceFilter(IfaceFilter()),
	)
	if err != nil {
		panic(err)
	}

	for entry := range ch {
		fmt.Println(entry.Name)
	}
}
