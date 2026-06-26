package trace

import (
	"net"
	"time"
)

const (
	MaxFld     = 20
	MinPort    = 1024
	MaxPort    = 65535
	MaxPacket  = 65535
	MinPacket  = 28
	MaxSequence = 65536
	MinSequence = 33000
)

// Protocol selects the probe protocol.
type Protocol int

const (
	ProtoICMP Protocol = iota
	ProtoUDP
	ProtoTCP
	ProtoSCTP
)

// DisplayMode selects the output mode.
type DisplayMode int

const (
	DisplayReport DisplayMode = iota
	DisplayCurses
	DisplayGTK
	DisplaySplit
	DisplayRaw
	DisplayXML
	DisplayCSV
	DisplayTXT
	DisplayJSON
)

// Config holds all mtr runtime options, mirroring struct mtr_ctl.
type Config struct {
	MaxPing      int
	WaitTime     float64
	GraceTime    float64
	Hostname     string
	Hostnames    []string // multiple targets from -F or positional args
	InterfaceName    string
	InterfaceAddress string
	LocalHostname    string

	IPInfoNo   int
	IPInfoMax  int
	IPInfoProvider4 string
	IPInfoProvider6 string

	PacketSize int
	BitPattern int
	TOS        int
	Mark       uint32

	AF       int // 0=unspec, 4=IPv4, 6=IPv6
	Protocol Protocol
	FstTTL   int
	MaxTTL   int
	DueTTL   int
	MaxUnknown    int
	MaxDisplayPath int
	RemotePort int
	LocalPort  int
	ProbeTimeout int // microseconds

	FldActive string // active fields string, e.g. "LS NABWV"

	Display      DisplayMode
	DisplayModeN int // sub-display mode (blockmap etc.)
	Interactive  bool

	ForceMaxPing bool
	UseDNS       bool
	ShowIPs      bool
	EnableMPLS   bool
	DNS          bool
	ReportWide   bool

	// Resolved target address (filled after DNS resolution).
	RemoteAddr net.IP

	// File to read hostnames from (-F flag).
	FilenameHosts string
}

// DefaultConfig returns the default configuration matching mtr's defaults.
func DefaultConfig() *Config {
	return &Config{
		MaxPing:      10,
		WaitTime:     1.0,
		GraceTime:    5.0,
		DNS:          true,
		UseDNS:       true,
		PacketSize:   64,
		AF:           0, // unspec
		Protocol:     ProtoICMP,
		FstTTL:       1,
		MaxTTL:       30,
		DueTTL:       0,
		MaxUnknown:   12,
		MaxDisplayPath: 8,
		ProbeTimeout: int((10 * time.Second).Microseconds()),
		Interactive:  true,
		FldActive:    "LS NABWV",
		IPInfoNo:     -1,
		IPInfoMax:    -1,
		IPInfoProvider4: "origin.asn.cymru.com",
		IPInfoProvider6: "origin6.asn.cymru.com",
		BitPattern:   0,
	}
}
