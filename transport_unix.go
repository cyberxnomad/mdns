//go:build unix

package mdns

import (
	"syscall"
)

// Set socket options to allow port reuse.
// This allows multiple sockets to bind to the same port.
func setReusePort(fd uintptr) error {
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return err
	}

	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
