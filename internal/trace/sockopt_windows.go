//go:build windows

package trace

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	// ipv6UnicastHops is sourced from golang.org/x/sys/windows.IPV6_UNICAST_HOPS.
	ipv6UnicastHops = windows.IPV6_UNICAST_HOPS
	// ipv6TClass is IPV6_TCLASS (39 / 0x27). Not exported by golang.org/x/sys/windows;
	// value taken from the Windows SDK header ws2ipdef.h.
	ipv6TClass = 39
)

// setTTL sets the IP TTL (or IPv6 hop limit) on a PacketConn.
func setTTL(conn net.PacketConn, ttl int, af int) error {
	rc, err := getRawConn(conn)
	if err != nil {
		return err
	}

	var setErr error
	err = rc.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		if af == 6 {
			setErr = syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6UnicastHops, ttl)
		} else {
			setErr = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
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
		h := syscall.Handle(fd)
		if af == 6 {
			setErr = syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6TClass, tos)
		} else {
			setErr = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
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
