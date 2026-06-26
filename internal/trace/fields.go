package trace

import "fmt"

// Field represents a displayable statistic column, mirroring mtr's data_fields[].
type Field struct {
	Key    byte
	Descr  string
	Title  string
	Format string
	Length int
	// Getter returns the field value from a HopSnapshot.
	// Float fields return microseconds; callers divide by 1000 for ms.
	Getter func(h *HopSnapshot) int
}

// DataFields mirrors mtr's data_fields[] array exactly.
var DataFields = []Field{
	{Key: ' ', Descr: "<sp>: Space between fields", Title: " ", Format: " ", Length: 1,
		Getter: func(h *HopSnapshot) int { return (h.Xmit - h.Transit) - h.Returned }},
	{Key: 'L', Descr: "L: Loss Ratio", Title: "Loss%", Format: " %4.1f%%", Length: 6,
		Getter: func(h *HopSnapshot) int {
			// mtr: 1000 * (100 - (100.0 * returned / (xmit - transit)))
			completed := h.Xmit - h.Transit
			if completed == 0 {
				return 0
			}
			return int(1000.0 * (100.0 - (100.0 * float64(h.Returned) / float64(completed))))
		}},
	{Key: 'D', Descr: "D: Dropped Packets", Title: "Drop", Format: " %4d", Length: 5,
		Getter: func(h *HopSnapshot) int { return (h.Xmit - h.Transit) - h.Returned }},
	{Key: 'R', Descr: "R: Received Packets", Title: "Rcv", Format: " %5d", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Returned }},
	{Key: 'S', Descr: "S: Sent Packets", Title: "Snt", Format: " %5d", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Xmit }},
	{Key: 'N', Descr: "N: Newest RTT(ms)", Title: "Last", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Last }},
	{Key: 'B', Descr: "B: Min/Best RTT(ms)", Title: "Best", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Best }},
	{Key: 'A', Descr: "A: Average RTT(ms)", Title: "Avg", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Avg }},
	{Key: 'W', Descr: "W: Max/Worst RTT(ms)", Title: "Wrst", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.Worst }},
	{Key: 'V', Descr: "V: Standard Deviation", Title: "StDev", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.StDev }},
	{Key: 'G', Descr: "G: Geometric Mean", Title: "Gmean", Format: " %5.1f", Length: 6,
		Getter: func(h *HopSnapshot) int { return h.GMean }},
	{Key: 'J', Descr: "J: Current Jitter", Title: "Jttr", Format: " %4.1f", Length: 5,
		Getter: func(h *HopSnapshot) int { return h.Jitter }},
	{Key: 'M', Descr: "M: Jitter Mean/Avg.", Title: "Javg", Format: " %4.1f", Length: 5,
		Getter: func(h *HopSnapshot) int { return h.JAvg }},
	{Key: 'X', Descr: "X: Worst Jitter", Title: "Jmax", Format: " %4.1f", Length: 5,
		Getter: func(h *HopSnapshot) int { return h.JWorst }},
	{Key: 'I', Descr: "I: Interarrival Jitter", Title: "Jint", Format: " %4.1f", Length: 5,
		Getter: func(h *HopSnapshot) int { return h.JInta }},
}

// FieldIndex maps field key byte to index in DataFields.
var FieldIndex [256]int

func init() {
	for i := range FieldIndex {
		FieldIndex[i] = -1
	}
	for i, f := range DataFields {
		FieldIndex[f.Key] = i
	}
}

// AvailableOptions returns the string of available field key characters.
func AvailableOptions() string {
	var opts []byte
	for _, f := range DataFields {
		opts = append(opts, f.Key)
	}
	opts = append(opts, '_')
	return string(opts)
}

// FormatField formats a field value from a HopSnapshot, handling the space field
// and float/int distinction correctly. Matches mtr's report_close rendering logic.
func FormatField(f Field, h *HopSnapshot) string {
	// The space field (key=' ') has format " " with no verb — just return it literally.
	if f.Key == ' ' {
		return f.Format
	}
	val := f.Getter(h)
	if IsFloatFormat(f.Format) {
		return fmt.Sprintf(f.Format, float64(val)/1000.0)
	}
	return fmt.Sprintf(f.Format, val)
}

// FormatFieldFloat formats a float field value (usec -> ms) using the field's format.
func FormatFieldFloat(format string, usec int) string {
	return fmt.Sprintf(format, float64(usec)/1000.0)
}

// FormatFieldInt formats an integer field value using the field's format.
func FormatFieldInt(format string, val int) string {
	return fmt.Sprintf(format, val)
}

// IsFloatFormat returns true if the format string contains a float verb
// (f, e, or g) after a valid '%' directive, correctly skipping '%%' escapes.
func IsFloatFormat(format string) bool {
	for i := 0; i < len(format); i++ {
		if format[i] == '%' {
			i++
			// skip flags, width, and precision characters
			for i < len(format) && (format[i] >= '0' && format[i] <= '9' || format[i] == '.' || format[i] == '-' || format[i] == '+') {
				i++
			}
			if i < len(format) && (format[i] == 'f' || format[i] == 'e' || format[i] == 'g') {
				return true
			}
		}
	}
	return false
}
