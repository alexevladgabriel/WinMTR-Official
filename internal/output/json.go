package output

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

type jsonReport struct {
	Report struct {
		Mtr  jsonMtr   `json:"mtr"`
		Hubs []jsonHub `json:"hubs"`
	} `json:"report"`
}

type jsonMtr struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	TOS        int    `json:"tos"`
	Tests      int    `json:"tests"`
	PSize      string `json:"psize"`
	BitPattern string `json:"bitpattern"`
}

type jsonHub map[string]interface{}

// JSON writes the JSON output (-j), matching mtr's json_close.
func JSON(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	psize := ""
	if cfg.PacketSize >= 0 {
		psize = fmt.Sprintf("%d", cfg.PacketSize)
	} else {
		psize = fmt.Sprintf("rand(%d-%d)", trace.MinPacket, -cfg.PacketSize)
	}

	bitpattern := ""
	if cfg.BitPattern >= 0 {
		bitpattern = fmt.Sprintf("0x%02X", byte(cfg.BitPattern))
	} else {
		bitpattern = "rand(0x00-FF)"
	}

	report := jsonReport{}
	report.Report.Mtr = jsonMtr{
		Src:        cfg.LocalHostname,
		Dst:        cfg.Hostname,
		TOS:        cfg.TOS,
		Tests:      cfg.MaxPing,
		PSize:      psize,
		BitPattern: bitpattern,
	}

	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		name := snprintAddr(cfg, hop.Addr)

		hub := jsonHub{
			"count": at + 1,
			"host":  name,
		}

		for _, c := range cfg.FldActive {
			idx := trace.FieldIndex[byte(c)]
			if idx <= 0 {
				continue // skip space field
			}
			f := trace.DataFields[idx]
			val := f.Getter(hop)
			title := strings.TrimSpace(f.Title)
			if trace.IsFloatFormat(f.Format) {
				hub[title] = roundFloat(float64(val)/1000.0, 5)
			} else {
				hub[title] = val
			}
		}

		report.Report.Hubs = append(report.Report.Hubs, hub)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
	}
}

func roundFloat(val float64, precision int) float64 {
	p := math.Pow(10, float64(precision))
	return math.Round(val*p) / p
}
