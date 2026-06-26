package output

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s)) //nolint:errcheck // strings.Builder.Write never errors
	return b.String()
}

// XML writes the XML output (-x), matching mtr's xml_close.
func XML(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	fmt.Fprintln(w, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	fmt.Fprintf(w, `<MTR SRC="%s" DST="%s"`, xmlEscape(cfg.LocalHostname), xmlEscape(cfg.Hostname))
	fmt.Fprintf(w, ` TOS="0x%X"`, cfg.TOS)
	if cfg.PacketSize >= 0 {
		fmt.Fprintf(w, ` PSIZE="%d"`, cfg.PacketSize)
	} else {
		fmt.Fprintf(w, ` PSIZE="rand(%d-%d)"`, trace.MinPacket, -cfg.PacketSize)
	}
	if cfg.BitPattern >= 0 {
		fmt.Fprintf(w, ` BITPATTERN="0x%02X"`, byte(cfg.BitPattern))
	} else {
		fmt.Fprintf(w, ` BITPATTERN="rand(0x00-FF)"`)
	}
	fmt.Fprintf(w, ` TESTS="%d"`, cfg.MaxPing)
	fmt.Fprintln(w, ">")

	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		name := snprintAddr(cfg, hop.Addr)

		fmt.Fprintf(w, "    <HUB COUNT=\"%d\" HOST=\"%s\">\n", at+1, xmlEscape(name))

		for _, c := range cfg.FldActive {
			idx := trace.FieldIndex[byte(c)]
			if idx <= 0 {
				continue // skip space field
			}
			f := trace.DataFields[idx]
			val := f.Getter(hop)

			// XML doesn't allow "%" in tag names.
			title := f.Title
			if title == "Loss%" {
				title = "Loss"
			}
			title = strings.TrimSpace(title)

			var valStr string
			if trace.IsFloatFormat(f.Format) {
				valStr = strings.TrimSpace(fmt.Sprintf(f.Format, float64(val)/1000.0))
			} else {
				valStr = strings.TrimSpace(fmt.Sprintf(f.Format, val))
			}

			fmt.Fprintf(w, "        <%s>%s</%s>\n", title, valStr, title)
		}

		fmt.Fprintln(w, "    </HUB>")
	}

	fmt.Fprintln(w, "</MTR>")
}
