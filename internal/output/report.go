package output

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	appdns "github.com/WinMTR/WinMTR-Official/internal/dns"
	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

var resolver = appdns.NewResolver(5 * time.Minute)

var (
	asnCache     *appdns.ASNCache
	asnCacheOnce sync.Once
)

func getASNCache(provider4, provider6 string) *appdns.ASNCache {
	asnCacheOnce.Do(func() {
		asnCache = appdns.NewASNCache(provider4, provider6)
	})
	return asnCache
}

// snprintAddr formats the display name for a hop address, matching mtr's snprint_addr.
func snprintAddr(cfg *trace.Config, addr net.IP) string {
	if addr == nil {
		return "???"
	}
	if !cfg.DNS {
		return addr.String()
	}
	hostname := resolver.LookupAddr(addr)
	if cfg.ShowIPs && hostname != addr.String() {
		return fmt.Sprintf("%s (%s)", hostname, addr.String())
	}
	return hostname
}

// fmtIPInfo returns the formatted ipinfo string for an address, matching mtr's fmt_ipinfo.
func fmtIPInfo(cfg *trace.Config, addr net.IP) string {
	if cfg.IPInfoNo < 0 || addr == nil {
		return ""
	}
	cache := getASNCache(cfg.IPInfoProvider4, cfg.IPInfoProvider6)
	info := cache.Lookup(addr)
	val := info.GetField(cfg.IPInfoNo)
	width := 12 // default
	if cfg.IPInfoNo < len(appdns.IIWidth) {
		width = appdns.IIWidth[cfg.IPInfoNo]
	}
	prefix := ""
	if cfg.IPInfoNo == 0 {
		prefix = "AS"
	}
	return fmt.Sprintf("%s%-*s", prefix, width, val)
}

// Report writes the report mode output (-r/-w), matching mtr's report_close.
func Report(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	// Print start time.
	fmt.Fprintf(w, "Start: %s\n", time.Now().Format("2006-01-02T15:04:05-0700"))

	// Determine max hostname length for wide mode.
	// mtr starts with len_hosts = 33 (non-wide default).
	lenHosts := 33
	if len(cfg.LocalHostname) > lenHosts {
		lenHosts = len(cfg.LocalHostname)
	}

	if cfg.ReportWide {
		// In wide mode, scan all hops and find the longest hostname.
		for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
			name := snprintAddr(cfg, hops[at].Addr)
			if len(name) > lenHosts {
				lenHosts = len(name)
			}
		}
	}

	// mtr adjusts lenHosts for ipinfo width when enabled.
	// len_tmp is the total width used by the HOST column in the header.
	// When IPInfo is active the data row emits: ipinfo + hostname padded to lenHosts.
	// The header must account for that full width so columns align.
	lenTmp := lenHosts
	if cfg.IPInfoNo >= 0 {
		iiIdx := cfg.IPInfoNo
		if iiIdx >= len(appdns.IIWidth) {
			iiIdx = iiIdx % len(appdns.IIWidth)
		}
		if cfg.ReportWide {
			lenHosts++ // space between ipinfo and hostname
		}
		// In both wide and non-wide mode the header HOST field must span
		// the ipinfo prefix width plus the hostname width so that data rows
		// (which emit ipinfo immediately before the hostname) align with it.
		lenTmp += appdns.IIWidth[iiIdx]
		if cfg.IPInfoNo == 0 {
			lenTmp += 2 // "AS" prefix
		}
	}

	// Header line.
	// mtr: snprintf(fmt, sizeof(fmt), "HOST: %%-%ds", len_tmp);
	header := fmt.Sprintf("HOST: %-*s", lenTmp, cfg.LocalHostname)

	for _, c := range cfg.FldActive {
		idx := trace.FieldIndex[byte(c)]
		if idx < 0 {
			continue
		}
		f := trace.DataFields[idx]
		header += fmt.Sprintf("%*s", f.Length, f.Title)
	}
	fmt.Fprintln(w, header)

	// Hop lines.
	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		name := snprintAddr(cfg, hop.Addr)

		var line string
		if cfg.IPInfoNo >= 0 {
			// mtr: " %2d. %s%-Ns" with ipinfo prefix
			ipinfo := fmtIPInfo(cfg, hop.Addr)
			line = fmt.Sprintf(" %2d. %s%-*s", at+1, ipinfo, lenHosts, name)
		} else {
			line = fmt.Sprintf(" %2d.|-- %-*s", at+1, lenHosts, name)
		}

		// In wide mode, pad line to header width; in non-wide, use lenHosts.
		for _, c := range cfg.FldActive {
			idx := trace.FieldIndex[byte(c)]
			if idx < 0 {
				continue
			}
			f := trace.DataFields[idx]
			line += trace.FormatField(f, hop)
		}
		fmt.Fprintln(w, line)

		// MPLS labels.
		if cfg.EnableMPLS && len(hop.Mpls.Labels) > 0 {
			for _, l := range hop.Mpls.Labels {
				fmt.Fprintf(w, "       [MPLS: Lbl %d TC %d S %d TTL %d]\n",
					l.Label, l.TC, l.S, l.TTL)
			}
		}

		// ECMP paths.
		for z := 0; z < cfg.MaxDisplayPath && z < len(hop.Addrs); z++ {
			addr2 := hop.Addrs[z]
			if addr2 == nil || addr2.Equal(hop.Addr) {
				continue
			}
			name2 := snprintAddr(cfg, addr2)
			fmt.Fprintf(w, "        %-*s\n", lenHosts, name2)
		}
	}
}

// FormatAddr formats addr as string, stripping trailing spaces.
func FormatAddr(addr net.IP) string {
	if addr == nil {
		return "???"
	}
	return strings.TrimSpace(addr.String())
}
