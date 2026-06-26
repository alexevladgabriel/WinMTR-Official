//go:build windows

package trace

// ICMPProber on Windows uses IcmpSendEcho from iphlpapi.dll — the same
// approach as the legacy WinMTR.  Raw ICMP sockets on Windows cannot
// receive ICMP Time Exceeded messages reliably, but IcmpSendEcho handles
// the full send+receive cycle internally, including TTL expiry replies.
//
// PARITY NOTE: IcmpSendEcho reports RoundTripTime as a whole-millisecond
// ULONG, so every RTT here is quantized to 1ms.  The Last/Avg/Best/Wrst/
// StDev columns therefore render with a .0 fraction (e.g. "5.0") where
// raw-socket mtr on Unix — which timestamps with microsecond precision —
// shows true 0.1ms granularity (e.g. "5.3").  This is an intentional
// trade-off: IcmpSendEcho runs unprivileged, whereas a high-resolution
// raw-socket prober would require Administrator elevation.  See the Unix
// path in icmp.go for the microsecond-precision implementation.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows ICMP reply status codes (from iphlpapi.h).
const (
	ipSuccess           = 0
	ipTTLExpiredTransit = 11013
	ipTTLExpiredReassem = 11014
	ipReqTimedOut       = 11010
	ipFlagDontFragment  = 0x02
)

var (
	modiphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = modiphlpapi.NewProc("IcmpSendEcho")
)

// ipOptionInfo mirrors IP_OPTION_INFORMATION from the Windows SDK.
// Must match the C struct layout exactly.
type ipOptionInfo struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY from the Windows SDK.
// On 64-bit Windows the Data pointer is 8 bytes; Go's uintptr matches.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInfo
}

// ICMPProber uses the Windows ICMP API for traceroute probes.
type ICMPProber struct {
	handle uintptr
	cfg    *Config
	id     int
}

// NewICMPProber opens a Windows ICMP handle via IcmpCreateFile.
func NewICMPProber(cfg *Config) (*ICMPProber, error) {
	h, _, err := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return nil, fmt.Errorf("IcmpCreateFile failed: %w", err)
	}
	return &ICMPProber{
		handle: h,
		cfg:    cfg,
		id:     os.Getpid() & 0xffff,
	}, nil
}

// Send sends one ICMP echo probe at the given TTL and blocks until a reply
// arrives or the timeout expires.  Mirrors legacy WinMTR's TraceThread logic.
func (p *ICMPProber) Send(dst net.IP, ttl int, timeout time.Duration, seq int) (*ProbeResult, error) {
	ip4 := dst.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("Windows ICMP API requires IPv4; use -4 flag")
	}

	// Build payload filled with the configured bit pattern.
	pktSize := p.cfg.PacketSize
	if pktSize < 8 {
		pktSize = 64
	}
	payloadLen := pktSize - 8
	if payloadLen < 1 {
		payloadLen = 1
	}
	payload := make([]byte, payloadLen)
	pat := byte(p.cfg.BitPattern & 0xff)
	for i := range payload {
		payload[i] = pat
	}

	opts := ipOptionInfo{
		TTL:   uint8(ttl),
		TOS:   uint8(p.cfg.TOS),
		Flags: ipFlagDontFragment,
	}

	// Reply buffer: ICMP_ECHO_REPLY + payload + safety margin.
	replyBufSize := uintptr(unsafe.Sizeof(icmpEchoReply{})) + uintptr(payloadLen) + 8
	replyBuf := make([]byte, replyBufSize)

	// IcmpSendEcho takes IPAddr as a uint32 in network byte order.
	// On little-endian Windows, reading net.IP bytes as little-endian gives
	// the same uint32 value that Winsock's inet_addr() produces.
	dstAddr := uintptr(binary.BigEndian.Uint32(ip4))

	timeoutMs := uint32(timeout.Milliseconds())
	if timeoutMs == 0 {
		timeoutMs = 10000
	}

	start := time.Now()

	// IcmpSendEcho(Handle, Dest, RequestData, RequestSize,
	//              RequestOptions, ReplyBuffer, ReplySize, Timeout)
	count, _, _ := procIcmpSendEcho.Call(
		p.handle,
		dstAddr,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(payloadLen)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(uint32(replyBufSize)),
		uintptr(timeoutMs),
	)

	runtime.KeepAlive(payload)
	runtime.KeepAlive(replyBuf)

	rtt := time.Since(start)

	if count == 0 {
		// Timeout or unrecoverable error.
		return &ProbeResult{TTL: ttl, RTT: timeout, Err: -1}, nil
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))

	// Convert IPAddr (network byte order uint32) back to net.IP.
	addrBytes := make(net.IP, 4)
	binary.BigEndian.PutUint32(addrBytes, reply.Address)

	// RoundTripTime is whole milliseconds (see PARITY NOTE above). For
	// sub-millisecond hops it reports 0; fall back to the locally measured
	// send/receive delta so the first/LAN hop still shows a real value.
	replyRTT := time.Duration(reply.RoundTripTime) * time.Millisecond
	if replyRTT == 0 {
		replyRTT = rtt
	}

	switch reply.Status {
	case ipSuccess:
		return &ProbeResult{
			TTL:     ttl,
			RTT:     replyRTT,
			Addr:    addrBytes,
			Reached: true,
		}, nil

	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		return &ProbeResult{
			TTL:  ttl,
			RTT:  replyRTT,
			Addr: addrBytes,
			Err:  11, // ICMP Time Exceeded
		}, nil

	case ipReqTimedOut:
		return &ProbeResult{TTL: ttl, RTT: replyRTT, Err: -1}, nil

	default:
		// Destination unreachable or other ICMP error — hop is reachable.
		return &ProbeResult{
			TTL:     ttl,
			RTT:     replyRTT,
			Addr:    addrBytes,
			Reached: true,
		}, nil
	}
}

// Close releases the Windows ICMP handle.
func (p *ICMPProber) Close() error {
	if p.handle != 0 {
		ret, _, _ := procIcmpCloseHandle.Call(p.handle)
		p.handle = 0
		if ret == 0 {
			return fmt.Errorf("IcmpCloseHandle failed")
		}
	}
	return nil
}
