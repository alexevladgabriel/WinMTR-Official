//go:build !windows

package trace

import (
	"fmt"
	"net"
	"syscall"
)

// setTTL sets the IP TTL (or IPv6 hop limit) on a PacketConn.
func setTTL(conn net.PacketConn, ttl int, af int) error {
	rc, err := getRawConn(conn)
	if err != nil {
		return err
	}

	var setErr error
	err = rc.Control(func(fd uintptr) {
		if af == 6 {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// setTOS sets the IP TOS field on a PacketConn.
func setTOS(conn net.PacketConn, tos int, af int) error {
	rc, err := getRawConn(conn)
	if err != nil {
		return err
	}

	var setErr error
	err = rc.Control(func(fd uintptr) {
		if af == 6 {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
		} else {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// getRawConn extracts syscall.RawConn from a net.PacketConn.
func getRawConn(conn net.PacketConn) (syscall.RawConn, error) {
	type rawConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if rc, ok := conn.(rawConner); ok {
		return rc.SyscallConn()
	}
	return nil, fmt.Errorf("connection does not support SyscallConn")
}
