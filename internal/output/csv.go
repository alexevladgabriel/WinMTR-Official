package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

const mtrVersion = "0.1.0"

// CSV writes the CSV output (-C), matching mtr's csv_close.
func CSV(w io.Writer, cfg *trace.Config, hops []trace.HopSnapshot, maxHop int) {
	now := time.Now().Unix()
	cw := csv.NewWriter(w)
	headerPrinted := false

	for at := cfg.FstTTL - 1; at < maxHop && at < len(hops); at++ {
		hop := &hops[at]
		name := snprintAddr(cfg, hop.Addr)

		// Print header on first row.
		if !headerPrinted {
			header := []string{"Mtr_Version", "Start_Time", "Status", "Host", "Hop", "Ip"}
			if cfg.IPInfoNo == 0 {
				header = append(header, "Asn")
			}
			for _, c := range cfg.FldActive {
				idx := trace.FieldIndex[byte(c)]
				if idx < 0 {
					continue
				}
				f := trace.DataFields[idx]
				header = append(header, f.Title)
			}
			if err := cw.Write(header); err != nil {
				fmt.Fprintf(w, "csv write error: %v\n", err)
				return
			}
			headerPrinted = true
		}

		record := []string{
			"MTR." + mtrVersion,
			fmt.Sprintf("%d", now),
			"OK",
			cfg.Hostname,
			fmt.Sprintf("%d", at+1),
			name,
		}

		for _, c := range cfg.FldActive {
			idx := trace.FieldIndex[byte(c)]
			if idx < 0 {
				continue
			}
			f := trace.DataFields[idx]
			val := f.Getter(hop)
			if trace.IsFloatFormat(f.Format) {
				record = append(record, fmt.Sprintf("%.2f", float64(val)/1000.0))
			} else {
				record = append(record, fmt.Sprintf("%d", val))
			}
		}

		if err := cw.Write(record); err != nil {
			fmt.Fprintf(w, "csv write error: %v\n", err)
			return
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		fmt.Fprintf(w, "csv flush error: %v\n", err)
	}
}
