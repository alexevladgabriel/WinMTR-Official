package output

import (
	"fmt"
	"io"

	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

// Raw writes the raw output (-l), matching mtr's raw format from FORMATS file.
//
// Format:
//
//	h <pos> <host IP>           - host line
//	d <pos> <hostname>          - DNS resolved name
//	x <pos> <seqnum>            - xmit line
//	p <pos> <pingtime(usec)> <seqnum>  - ping result
//	m <pos> <label> <tc> <s> <ttl>     - MPLS line
func Raw(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		pos := at + 1

		// Host line.
		if hop.Addr != nil {
			fmt.Fprintf(w, "h %d %s\n", pos, hop.Addr.String())
		}

		// DNS line.
		if cfg.DNS && hop.Addr != nil {
			hostname := resolver.LookupAddr(hop.Addr)
			if hostname != hop.Addr.String() {
				fmt.Fprintf(w, "d %d %s\n", pos, hostname)
			}
		}

		// Xmit and ping lines.
		for seq := 0; seq < hop.Xmit; seq++ {
			fmt.Fprintf(w, "x %d %d\n", pos, seq)
		}
		if hop.Returned > 0 {
			fmt.Fprintf(w, "p %d %d %d\n", pos, hop.Avg, hop.Returned)
		}

		// MPLS lines.
		if cfg.EnableMPLS {
			for _, l := range hop.Mpls.Labels {
				fmt.Fprintf(w, "m %d %d %d %d %d\n", pos, l.Label, l.TC, l.S, l.TTL)
			}
		}
	}
}

// Split writes the split output (-p), matching mtr's split format from FORMATS file.
//
// Format:
//
//	<pos> <host> <loss%> <rcvd> <sent> <best> <avg> <worst>
func Split(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		pos := at + 1

		host := "???"
		if hop.Addr != nil {
			host = snprintAddr(cfg, hop.Addr)
		}

		loss := 0.0
		if hop.Xmit > 0 {
			loss = float64(hop.Xmit-hop.Returned) / float64(hop.Xmit) * 100.0
		}

		fmt.Fprintf(w, "%d %s %.1f%% %d %d %.1f %.1f %.1f\n",
			pos, host, loss, hop.Returned, hop.Xmit,
			float64(hop.Best)/1000.0, float64(hop.Avg)/1000.0, float64(hop.Worst)/1000.0)
	}
}
