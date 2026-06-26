package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// cacheEntry is a cached DNS result with an expiry timestamp.
type cacheEntry struct {
	hostname string
	expires  time.Time
}

// Resolver provides DNS reverse-lookup resolution with caching.
type Resolver struct {
	cache sync.Map
	ttl   time.Duration
}

// NewResolver creates a resolver with the given cache TTL.
func NewResolver(ttl time.Duration) *Resolver {
	return &Resolver{ttl: ttl}
}

// LookupAddr returns the hostname for an IP, using cache when available.
// Expired entries are refreshed. Concurrent callers for the same key may
// each issue a lookup (sync.Map does not deduplicate), but for a CLI tool
// this is acceptable and avoids holding a lock across network I/O.
func (r *Resolver) LookupAddr(ip net.IP) string {
	key := ip.String()

	if v, ok := r.cache.Load(key); ok {
		e := v.(*cacheEntry)
		if time.Now().Before(e.expires) {
			return e.hostname
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, key)

	hostname := key
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	r.cache.Store(key, &cacheEntry{hostname: hostname, expires: time.Now().Add(r.ttl)})
	return hostname
}
