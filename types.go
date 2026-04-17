package mdns

import (
	"golang.org/x/net/dns/dnsmessage"
)

type RecordType uint16

const (
	TypeA    = RecordType(dnsmessage.TypeA)
	TypeAAAA = RecordType(dnsmessage.TypeAAAA)
	TypePTR  = RecordType(dnsmessage.TypePTR)
	TypeTXT  = RecordType(dnsmessage.TypeTXT)
	TypeSRV  = RecordType(dnsmessage.TypeSRV)
	TypeANY  = RecordType(dnsmessage.TypeALL)
)

// NetworkStack defines bitmask for supported IP protocols.
type NetworkStack uint

const (
	IPv4 NetworkStack = 1 << iota
	IPv6
)

// Check if the stack includes the specified protocol.
func (n NetworkStack) Has(s NetworkStack) bool {
	return (n&s != 0)
}
