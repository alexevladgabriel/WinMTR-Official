package trace

import (
	"net"
	"time"
)

// ProbeResult holds the result of a single probe.
type ProbeResult struct {
	TTL     int
	Addr    net.IP // responding address
	RTT     time.Duration
	Err     int    // ICMP error type (0 = success)
	Reached bool   // true if destination was reached
	ICMPExt []byte // raw ICMP extension data (for MPLS parsing)
}

// Prober is the interface for sending probes at a specific TTL.
type Prober interface {
	// Send sends a probe with the given TTL and returns the result.
	Send(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error)
	// Close releases any resources.
	Close() error
}
