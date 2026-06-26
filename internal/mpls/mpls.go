package mpls

// Label represents a single MPLS label from ICMP extensions (RFC 4950).
type Label struct {
	Label uint32
	TC    uint8
	S     uint8
	TTL   uint8
}

// Stack holds the MPLS label stack for a hop.
type Stack struct {
	Labels []Label
}

// maxLabels is the maximum number of MPLS labels parsed per hop (mirrors
// trace.MaxLabels = 8 without creating a circular import).
const maxLabels = 8

// ParseICMPExtension extracts MPLS labels from an ICMP extension object.
// The extension data follows the ICMP payload per RFC 4884/4950.
//
// Extension header (4 bytes):
//
//	version (4 bits) | reserved (12 bits) | checksum (16 bits)
//
// Each extension object:
//
//	length (16 bits) | class-num (8 bits) | c-type (8 bits) | data...
//
// For MPLS (class=1, c-type=1), data is 4-byte label entries:
//
//	label (20 bits) | TC (3 bits) | S (1 bit) | TTL (8 bits)
func ParseICMPExtension(data []byte) *Stack {
	if len(data) < 8 {
		return nil
	}

	// Extension header: first 4 bytes.
	ver := (data[0] >> 4) & 0x0f
	if ver != 2 {
		return nil
	}

	offset := 4 // skip extension header
	stack := &Stack{}

	for offset+4 <= len(data) {
		objLen := int(data[offset])<<8 | int(data[offset+1])
		classNum := data[offset+2]
		cType := data[offset+3]

		if objLen < 4 || offset+objLen > len(data) {
			break
		}

		// MPLS: class-num=1, c-type=1
		if classNum == 1 && cType == 1 {
			lblData := data[offset+4 : offset+objLen]
			for i := 0; i+4 <= len(lblData); i += 4 {
				entry := uint32(lblData[i])<<24 | uint32(lblData[i+1])<<16 |
					uint32(lblData[i+2])<<8 | uint32(lblData[i+3])

				label := Label{
					Label: entry >> 12,
					TC:    uint8((entry >> 9) & 0x07),
					S:     uint8((entry >> 8) & 0x01),
					TTL:   uint8(entry & 0xff),
				}
				stack.Labels = append(stack.Labels, label)
				if len(stack.Labels) >= maxLabels {
					break
				}
			}
		}

		offset += objLen
	}

	if len(stack.Labels) == 0 {
		return nil
	}
	return stack
}
