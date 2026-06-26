//go:build !windows

package trace

import (
	"errors"
	"net"
	"syscall"
)

// rawControlTTL returns a control function that sets TTL and TOS on the raw fd.
func rawControlTTL(ttl, tos, af int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			if af == 6 {
				setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
			} else {
				setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			}
			if setErr != nil {
				return
			}
			if tos > 0 {
				if af == 6 {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
				} else {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
				}
			}
		})
		if err != nil {
			return err
		}
		return setErr
	}
}

// isConnRefused checks if an error is "connection refused".
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isTimeout checks if an error is a timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
