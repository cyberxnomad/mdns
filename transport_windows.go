//go:build windows

package mdns

import (
	"syscall"
)

// Set socket options to allow port reuse.
// This allows multiple sockets to bind to the same port.
func setReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
