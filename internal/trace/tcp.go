package trace

import (
	"fmt"
	"net"
	"time"
)

// TCPProber sends TCP SYN probes by attempting connections at varying TTLs.
type TCPProber struct {
	cfg *Config
}

// NewTCPProber creates a TCP prober.
func NewTCPProber(cfg *Config) *TCPProber {
	return &TCPProber{cfg: cfg}
}

// Send sends a TCP SYN probe by trying to connect with a specific TTL.
// Intermediate hops return ICMP Time Exceeded; the destination completes or resets.
func (p *TCPProber) Send(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	port := p.cfg.RemotePort
	if port == 0 {
		port = 80
	}

	network := "tcp4"
	if p.cfg.AF == 6 {
		network = "tcp6"
	}

	addr := net.JoinHostPort(dst.String(), fmt.Sprintf("%d", port))

	// We create a raw dialer with TTL set.
	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: p.localAddr(network),
	}
	dialer.Control = rawControlTTL(ttl, p.cfg.TOS, p.cfg.AF)

	start := time.Now()
	conn, err := dialer.Dial(network, addr)
	rtt := time.Since(start)

	if conn != nil {
		conn.Close()
		// Connection succeeded = destination reached.
		return &ProbeResult{
			TTL:     ttl,
			Addr:    dst,
			RTT:     rtt,
			Reached: true,
		}, nil
	}

	if err != nil {
		// Check if it's a connection refused (destination reached but port closed).
		if isConnRefused(err) {
			return &ProbeResult{
				TTL:     ttl,
				Addr:    dst,
				RTT:     rtt,
				Reached: true,
				Err:     3,
			}, nil
		}

		// Timeout = no response from this hop.
		if isTimeout(err) {
			return &ProbeResult{
				TTL: ttl,
				RTT: timeout,
				Err: -1,
			}, nil
		}

		// Other error - likely ICMP from an intermediate hop.
		// Unfortunately Go's net package doesn't expose the ICMP source.
		// For proper TCP probing we'd need raw sockets.
		return &ProbeResult{
			TTL: ttl,
			RTT: rtt,
			Err: 11,
		}, nil
	}

	return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
}

// Close is a no-op for TCP prober.
func (p *TCPProber) Close() error { return nil }

func (p *TCPProber) localAddr(network string) net.Addr {
	if p.cfg.InterfaceAddress == "" {
		return nil
	}
	addr, _ := net.ResolveTCPAddr(network, p.cfg.InterfaceAddress+":0")
	return addr
}
