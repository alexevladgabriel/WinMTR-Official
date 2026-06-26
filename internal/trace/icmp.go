//go:build !windows

package trace

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPProber sends ICMP echo probes using golang.org/x/net/icmp.
type ICMPProber struct {
	conn4   *icmp.PacketConn
	conn6   *icmp.PacketConn
	pc4     *ipv4.PacketConn
	pc6     *ipv6.PacketConn
	cfg     *Config
	id      int
	readBuf []byte
}

// NewICMPProber creates an ICMP prober. Requires root/admin on most systems.
func NewICMPProber(cfg *Config) (*ICMPProber, error) {
	p := &ICMPProber{
		cfg:     cfg,
		id:      os.Getpid() & 0xffff,
		readBuf: make([]byte, 1500),
	}

	listenAddr := cfg.InterfaceAddress
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	if cfg.AF == 6 {
		if listenAddr == "0.0.0.0" {
			listenAddr = "::"
		}
		c, err := icmp.ListenPacket("ip6:ipv6-icmp", listenAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot open ICMPv6 socket: %w (try running as root/administrator)", err)
		}
		p.conn6 = c
		p.pc6 = c.IPv6PacketConn()
	} else {
		c, err := icmp.ListenPacket("ip4:icmp", listenAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot open ICMP socket: %w (try running as root/administrator)", err)
		}
		p.conn4 = c
		p.pc4 = c.IPv4PacketConn()
	}

	return p, nil
}

// Send sends an ICMP echo request at the given TTL and waits for a reply.
func (p *ICMPProber) Send(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	if p.cfg.AF == 6 {
		return p.send6(dst, ttl, timeout, seq)
	}
	return p.send4(dst, ttl, timeout, seq)
}

func (p *ICMPProber) send4(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	// Set TTL via ipv4.PacketConn — this works reliably on all platforms.
	if err := p.pc4.SetTTL(ttl); err != nil {
		return nil, fmt.Errorf("set TTL: %w", err)
	}
	if p.cfg.TOS > 0 {
		if err := p.pc4.SetTOS(p.cfg.TOS); err != nil {
			fmt.Fprintf(os.Stderr, "warning: SetTOS: %v\n", err)
		}
	}

	// Build ICMP Echo Request using x/net/icmp.
	pktSize := p.cfg.PacketSize
	if pktSize <= 0 {
		pktSize = 64
	}
	// Payload = total size - 8 bytes ICMP header.
	payloadLen := pktSize - 8
	if payloadLen < 0 {
		payloadLen = 0
	}
	payload := make([]byte, payloadLen)
	pattern := byte(p.cfg.BitPattern & 0xff)
	for i := range payload {
		payload[i] = pattern
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  seq,
			Data: payload,
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("marshal ICMP: %w", err)
	}

	dstAddr := &net.IPAddr{IP: dst}

	// Set deadline.
	if err := p.conn4.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	start := time.Now()

	if _, err := p.conn4.WriteTo(wb, dstAddr); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	// Read replies.
	for {
		n, from, err := p.conn4.ReadFrom(p.readBuf)
		if err != nil {
			// Timeout.
			return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
		}
		rtt := time.Since(start)
		fromIP := extractIP(from)

		result := p.parseReply4(p.readBuf[:n], seq)
		if result == nil {
			if time.Since(start) >= timeout {
				return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
			}
			continue
		}

		result.TTL = ttl
		result.RTT = rtt
		result.Addr = fromIP
		if fromIP.Equal(dst) {
			result.Reached = true
		}
		return result, nil
	}
}

func (p *ICMPProber) send6(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	if err := p.pc6.SetHopLimit(ttl); err != nil {
		return nil, fmt.Errorf("set hop limit: %w", err)
	}
	if p.cfg.TOS > 0 {
		if err := p.pc6.SetTrafficClass(p.cfg.TOS); err != nil {
			fmt.Fprintf(os.Stderr, "warning: SetTrafficClass: %v\n", err)
		}
	}

	pktSize := p.cfg.PacketSize
	if pktSize <= 0 {
		pktSize = 64
	}
	payloadLen := pktSize - 8
	if payloadLen < 0 {
		payloadLen = 0
	}
	payload := make([]byte, payloadLen)
	pattern := byte(p.cfg.BitPattern & 0xff)
	for i := range payload {
		payload[i] = pattern
	}

	msg := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  seq,
			Data: payload,
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("marshal ICMPv6: %w", err)
	}

	dstAddr := &net.IPAddr{IP: dst}

	if err := p.conn6.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	start := time.Now()

	if _, err := p.conn6.WriteTo(wb, dstAddr); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	for {
		n, from, err := p.conn6.ReadFrom(p.readBuf)
		if err != nil {
			return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
		}
		rtt := time.Since(start)
		fromIP := extractIP(from)

		result := p.parseReply6(p.readBuf[:n], seq)
		if result == nil {
			if time.Since(start) >= timeout {
				return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
			}
			continue
		}

		result.TTL = ttl
		result.RTT = rtt
		result.Addr = fromIP
		if fromIP.Equal(dst) {
			result.Reached = true
		}
		return result, nil
	}
}

// parseReply4 parses an IPv4 ICMP message from the raw buffer.
// The x/net/icmp conn on macOS strips the IP header, so we handle both cases.
func (p *ICMPProber) parseReply4(buf []byte, seq int) *ProbeResult {
	// On some platforms (Linux raw), the IP header is included.
	// On macOS, icmp.ListenPacket strips it. Detect by checking first nibble.
	icmpBuf := buf
	if len(buf) > 0 && (buf[0]>>4) == 4 {
		// IPv4 header present — skip it.
		ihl := int(buf[0]&0x0f) * 4
		if len(buf) < ihl+8 {
			return nil
		}
		icmpBuf = buf[ihl:]
	}

	// Parse as ICMP message.
	rm, err := icmp.ParseMessage(1, icmpBuf) // proto 1 = ICMP
	if err != nil {
		return nil
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			return nil
		}
		if echo.ID != p.id || echo.Seq != seq {
			return nil
		}
		return &ProbeResult{Reached: true}

	case ipv4.ICMPTypeTimeExceeded:
		return p.parseEmbedded4(rm.Body, seq, 11)

	case ipv4.ICMPTypeDestinationUnreachable:
		result := p.parseEmbedded4(rm.Body, seq, 3)
		if result != nil {
			result.Reached = true
		}
		return result
	}
	return nil
}

// parseEmbedded4 extracts the original echo request from a TimeExceeded or DestUnreachable body.
func (p *ICMPProber) parseEmbedded4(body icmp.MessageBody, seq int, errCode int) *ProbeResult {
	// The body should be a *icmp.TimeExceeded or *icmp.DstUnreach which embed the original datagram.
	var data []byte

	switch b := body.(type) {
	case *icmp.TimeExceeded:
		data = b.Data
	case *icmp.DstUnreach:
		data = b.Data
	default:
		// Fall back to raw bytes.
		raw, ok := body.(*icmp.RawBody)
		if !ok {
			return nil
		}
		data = raw.Data
	}

	if len(data) < 28 { // 20 (IP header) + 8 (ICMP header)
		return nil
	}

	// Original IP header.
	origIHL := int(data[0]&0x0f) * 4
	if len(data) < origIHL+8 {
		return nil
	}
	origICMP := data[origIHL:]
	// Parse the embedded echo request to match our id/seq.
	origID := int(origICMP[4])<<8 | int(origICMP[5])
	origSeq := int(origICMP[6])<<8 | int(origICMP[7])
	if origID != p.id || origSeq != seq {
		return nil
	}

	result := &ProbeResult{Err: errCode}
	// ICMP extensions for MPLS (RFC 4950) — appended after the original datagram.
	if len(data) > origIHL+8+4 {
		extOffset := origIHL + 8
		result.ICMPExt = data[extOffset:]
	}
	return result
}

// parseReply6 parses an ICMPv6 message.
func (p *ICMPProber) parseReply6(buf []byte, seq int) *ProbeResult {
	rm, err := icmp.ParseMessage(58, buf) // proto 58 = ICMPv6
	if err != nil {
		return nil
	}

	switch rm.Type {
	case ipv6.ICMPTypeEchoReply:
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			return nil
		}
		if echo.ID != p.id || echo.Seq != seq {
			return nil
		}
		return &ProbeResult{Reached: true}

	case ipv6.ICMPTypeTimeExceeded:
		return p.parseEmbedded6(rm.Body, seq, 3)

	case ipv6.ICMPTypeDestinationUnreachable:
		result := p.parseEmbedded6(rm.Body, seq, 1)
		if result != nil {
			result.Reached = true
		}
		return result
	}
	return nil
}

func (p *ICMPProber) parseEmbedded6(body icmp.MessageBody, seq int, errCode int) *ProbeResult {
	var data []byte

	switch b := body.(type) {
	case *icmp.TimeExceeded:
		data = b.Data
	case *icmp.DstUnreach:
		data = b.Data
	default:
		raw, ok := body.(*icmp.RawBody)
		if !ok {
			return nil
		}
		data = raw.Data
	}

	// IPv6 header is 40 bytes + 8 bytes for original ICMPv6 header.
	if len(data) < 48 {
		return nil
	}
	origICMP := data[40:]
	if len(origICMP) < 8 {
		return nil
	}
	origID := int(origICMP[4])<<8 | int(origICMP[5])
	origSeq := int(origICMP[6])<<8 | int(origICMP[7])
	if origID != p.id || origSeq != seq {
		return nil
	}
	return &ProbeResult{Err: errCode}
}

// Close releases the ICMP sockets.
func (p *ICMPProber) Close() error {
	var errs []error
	if p.conn4 != nil {
		if err := p.conn4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.conn6 != nil {
		if err := p.conn6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
