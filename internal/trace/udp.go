package trace

import (
	"fmt"
	"net"
	"os"
	"time"
)

// UDPProber sends UDP probes with varying TTLs and listens for ICMP responses.
type UDPProber struct {
	cfg      *Config
	sendConn net.PacketConn // persistent UDP send socket
	icmpConn net.PacketConn // for receiving ICMP errors
}

// NewUDPProber creates a UDP prober, opening both the ICMP listener and the
// UDP send socket once so they are reused across all Send calls. This avoids
// EADDRINUSE errors when a fixed LocalPort is configured (TIME_WAIT would
// prevent re-binding the same port each probe).
func NewUDPProber(cfg *Config) (*UDPProber, error) {
	// Determine the listen/bind address, defaulting to the wildcard when
	// InterfaceAddress is empty.
	listenAddr := cfg.InterfaceAddress
	if listenAddr == "" {
		if cfg.AF == 6 {
			listenAddr = "::"
		} else {
			listenAddr = "0.0.0.0"
		}
	}

	// Open ICMP listener to receive Time Exceeded / Dest Unreachable.
	icmpNet := "ip4:icmp"
	if cfg.AF == 6 {
		icmpNet = "ip6:ipv6-icmp"
	}
	icmpConn, err := net.ListenPacket(icmpNet, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot open ICMP socket for UDP probing: %w", err)
	}

	// Open the UDP send socket once.
	udpNet := "udp4"
	if cfg.AF == 6 {
		udpNet = "udp6"
	}
	laddr := fmt.Sprintf("%s:%d", listenAddr, cfg.LocalPort)
	sendConn, err := net.ListenPacket(udpNet, laddr)
	if err != nil {
		icmpConn.Close()
		return nil, fmt.Errorf("udp send listen: %w", err)
	}

	return &UDPProber{
		cfg:      cfg,
		sendConn: sendConn,
		icmpConn: icmpConn,
	}, nil
}

// Send sends a UDP probe at the given TTL and waits for an ICMP response.
func (p *UDPProber) Send(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	port := p.cfg.RemotePort
	if port == 0 {
		// Use high port numbers like traceroute (33434 + seq).
		port = 33434 + seq
	}

	// Set TTL on the persistent send socket.
	if err := setTTL(p.sendConn, ttl, p.cfg.AF); err != nil {
		return nil, fmt.Errorf("set TTL: %w", err)
	}
	if err := setTOS(p.sendConn, p.cfg.TOS, p.cfg.AF); err != nil {
		fmt.Fprintf(os.Stderr, "warning: setTOS: %v\n", err)
	}

	dstAddr := &net.UDPAddr{IP: dst, Port: port}

	// Build probe payload, guarding against a non-positive PacketSize
	// (e.g. from random-size mode passing a negative value via -s).
	pktSize := p.cfg.PacketSize
	if pktSize <= 0 {
		pktSize = 64
	}
	payload := make([]byte, pktSize)
	pattern := byte(p.cfg.BitPattern & 0xff)
	for i := range payload {
		payload[i] = pattern
	}

	// Set ICMP listener deadline.
	if err := p.icmpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	start := time.Now()

	if _, err := p.sendConn.WriteTo(payload, dstAddr); err != nil {
		return nil, fmt.Errorf("udp send: %w", err)
	}

	// Listen for ICMP Time Exceeded or Dest Unreachable.
	buf := make([]byte, 1500)
	for {
		n, from, err := p.icmpConn.ReadFrom(buf)
		if err != nil {
			return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
		}

		rtt := time.Since(start)
		fromIP := extractIP(from)

		// Parse ICMP to verify it's for our probe.
		if result := parseUDPICMPReply(buf[:n], dst, port, p.cfg.AF); result != nil {
			result.TTL = ttl
			result.RTT = rtt
			result.Addr = fromIP
			if fromIP.Equal(dst) {
				result.Reached = true
			}
			return result, nil
		}

		if time.Since(start) >= timeout {
			return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
		}
	}
}

// Close releases the persistent send and ICMP sockets.
func (p *UDPProber) Close() error {
	var firstErr error
	if p.sendConn != nil {
		if err := p.sendConn.Close(); err != nil {
			firstErr = err
		}
	}
	if p.icmpConn != nil {
		if err := p.icmpConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// parseUDPICMPReply checks if the ICMP reply contains our UDP probe.
func parseUDPICMPReply(buf []byte, dst net.IP, dstPort int, af int) *ProbeResult {
	if af == 6 {
		// IPv6: no IP header in raw socket reads.
		if len(buf) < 48+4 {
			return nil
		}
		icmpType := buf[0]
		if icmpType != 3 && icmpType != 1 { // Time Exceeded / Dest Unreachable
			return nil
		}
		// Original UDP header starts at offset 48 (8 ICMP + 40 IPv6).
		origUDP := buf[48:]
		if len(origUDP) < 4 {
			return nil
		}
		origDstPort := int(origUDP[2])<<8 | int(origUDP[3])
		if origDstPort != dstPort {
			return nil
		}
		result := &ProbeResult{Err: int(icmpType)}
		if icmpType == 1 {
			result.Reached = true
		}
		return result
	}

	// IPv4.
	if len(buf) < 20 {
		return nil
	}
	ihl := int(buf[0]&0x0f) * 4
	if len(buf) < ihl+8 {
		return nil
	}
	icmpBuf := buf[ihl:]
	icmpType := icmpBuf[0]

	if icmpType != 11 && icmpType != 3 {
		return nil
	}

	// Original IP header + UDP header inside ICMP.
	if len(icmpBuf) < 28+4 { // 8 ICMP + 20 IP + 4 UDP
		return nil
	}
	origIP := icmpBuf[8:]
	origIHL := int(origIP[0]&0x0f) * 4
	if len(origIP) < origIHL+4 {
		return nil
	}
	origUDP := origIP[origIHL:]
	origDstPort := int(origUDP[2])<<8 | int(origUDP[3])
	if origDstPort != dstPort {
		return nil
	}

	result := &ProbeResult{Err: int(icmpType)}
	if icmpType == 3 {
		result.Reached = true
	}

	// Check for ICMP extensions.
	extOffset := 8 + origIHL + 8
	if len(icmpBuf) > extOffset+4 {
		result.ICMPExt = icmpBuf[extOffset:]
	}

	return result
}
