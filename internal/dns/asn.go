package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ASN lookup via Team Cymru DNS TXT records.
// For IPv4: reverse octets + ".origin.asn.cymru.com"
// TXT response: "ASN | Route | Country | Registry | Allocated"

// IPInfo holds parsed ASN/IP information fields.
type IPInfo struct {
	ASN       string
	Route     string
	Country   string
	Registry  string
	Allocated string
	Raw       string
}

// ASNCache caches ASN lookups.
type ASNCache struct {
	mu        sync.RWMutex
	cache     map[string]*IPInfo
	provider4 string
	provider6 string
}

// NewASNCache creates an ASN lookup cache.
func NewASNCache(provider4, provider6 string) *ASNCache {
	return &ASNCache{
		cache:     make(map[string]*IPInfo),
		provider4: provider4,
		provider6: provider6,
	}
}

// Lookup returns IPInfo for the given IP address.
func (c *ASNCache) Lookup(ip net.IP) *IPInfo {
	key := ip.String()

	c.mu.RLock()
	if info, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		return info
	}
	c.mu.RUnlock()

	info := c.doLookup(ip)

	c.mu.Lock()
	c.cache[key] = info
	c.mu.Unlock()

	return info
}

func (c *ASNCache) doLookup(ip net.IP) *IPInfo {
	domain := c.buildDomain(ip)
	if domain == "" {
		return &IPInfo{ASN: "???"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil || len(txts) == 0 {
		return &IPInfo{ASN: "???"}
	}
	return parseTXT(txts[0])
}

func (c *ASNCache) buildDomain(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		// Reverse octets: 1.2.3.4 -> 4.3.2.1.origin.asn.cymru.com
		return fmt.Sprintf("%d.%d.%d.%d.%s",
			ip4[3], ip4[2], ip4[1], ip4[0], c.provider4)
	}

	if ip6 := ip.To16(); ip6 != nil {
		// Reverse all 32 nibbles (16 bytes) as required by Team Cymru.
		var parts []string
		for i := 15; i >= 0; i-- {
			parts = append(parts, fmt.Sprintf("%x.%x", ip6[i]&0xf, ip6[i]>>4))
		}
		return strings.Join(parts, ".") + "." + c.provider6
	}

	return ""
}

func parseTXT(txt string) *IPInfo {
	info := &IPInfo{Raw: txt}
	parts := strings.Split(txt, "|")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	if len(parts) >= 1 {
		info.ASN = parts[0]
	}
	if len(parts) >= 2 {
		info.Route = parts[1]
	}
	if len(parts) >= 3 {
		info.Country = parts[2]
	}
	if len(parts) >= 4 {
		info.Registry = parts[3]
	}
	if len(parts) >= 5 {
		info.Allocated = parts[4]
	}
	return info
}

// GetField returns the ipinfo field at the given index (0=ASN, 1=Route, etc.).
func (info *IPInfo) GetField(idx int) string {
	switch idx {
	case 0:
		return info.ASN
	case 1:
		return info.Route
	case 2:
		return info.Country
	case 3:
		return info.Registry
	case 4:
		return info.Allocated
	default:
		return info.ASN
	}
}

// IIWidth returns the display width for each ipinfo field (matches mtr's iiwidth[]).
var IIWidth = []int{12, 19, 4, 8, 11}
