package mdns

import "errors"

var (
	ErrNoEligibleIface    = errors.New("no eligible network interfaces found for mDNS")
	ErrFQDNLen            = errors.New("FQDN length exceeds 255 bytes")
	ErrDomainRequired     = errors.New("domain is required")
	ErrResponderNotServed = errors.New("responder not served")
	ErrResponderServed    = errors.New("responder already served")
	ErrServiceNotFound    = errors.New("service not registered")
	ErrServiceRegistered  = errors.New("service already registered")
	ErrServiceConflict    = errors.New("service name conflict detected")
)
