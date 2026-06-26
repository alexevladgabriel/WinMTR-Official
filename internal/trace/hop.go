package trace

import (
	"math"
	"net"
	"sync"
)

const (
	MaxHost    = 256
	MaxPath    = 128
	SavedPings = 400
	MaxLabels  = 8
)

// MPLSLabel represents a single MPLS label entry from ICMP extensions.
type MPLSLabel struct {
	Label uint32
	TC    uint8
	S     uint8
	TTL   uint8
}

// MPLS holds the MPLS label stack for a hop.
type MPLS struct {
	Labels []MPLSLabel
}

// HopStats holds per-hop statistics, mirroring mtr's nethost struct exactly.
type HopStats struct {
	mu sync.RWMutex

	Addr  net.IP   // latest address that responded
	Addrs []net.IP // all addresses seen (ECMP paths)
	Err   int      // last ICMP error code

	Xmit     int // packets sent
	Returned int // packets received
	Sent     int // per-cycle sent flag (reset on return)
	Up       int // host is up

	Last    int // last RTT in microseconds
	Best    int // best RTT in microseconds
	Worst   int // worst RTT in microseconds
	Avg     int // running average in microseconds
	GMean   int // geometric mean in microseconds
	Transit int // 1 if probe is in-flight, 0 otherwise (mtr uses this for loss calc)

	// Sum of squares of differences from current average (for stdev).
	SSD int64

	// Jitter fields (all in microseconds).
	Jitter int // current jitter |t1 - t0|
	JAvg   int // average jitter
	JWorst int // worst jitter
	JInta  int // interarrival jitter (RFC 1889)

	Saved       [SavedPings]int
	SavedSeqOff int
	Mpls        MPLS
	MplsByPath  [MaxPath]MPLS
}

func NewHopStats() *HopStats {
	h := &HopStats{}
	for i := range h.Saved {
		h.Saved[i] = -1 // -1 = no data
	}
	return h
}

// AddResult records a probe result for this hop.
// This mirrors mtr's net.c net_process_ping() logic exactly:
//
//	lines 280-327 of refs/refs/mtr/ui/net.c
func (h *HopStats) AddResult(rtt int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Step 1: Compute jitter BEFORE updating last (mtr lines 280-283).
	h.Jitter = rtt - h.Last
	if h.Jitter < 0 {
		h.Jitter = -h.Jitter
	}

	// Step 2: Update last (mtr line 285).
	h.Last = rtt

	// Step 3: On first return, initialize best/worst/gmean and zero jitter stats (mtr lines 287-292).
	if h.Returned < 1 {
		h.Best = rtt
		h.Worst = rtt
		h.GMean = rtt
		h.Avg = 0
		h.SSD = 0
		h.Jitter = 0
		h.JWorst = 0
		h.JInta = 0
	}

	// Step 4: Update best/worst (mtr lines 294-299).
	if rtt < h.Best {
		h.Best = rtt
	}
	if rtt > h.Worst {
		h.Worst = rtt
	}

	// Step 5: Update worst jitter (mtr lines 301-303).
	if h.Jitter > h.JWorst {
		h.JWorst = h.Jitter
	}

	// Step 6: Increment returned, compute avg/ssd with float intermediate (mtr lines 305-309).
	h.Returned++
	oldAvg := h.Avg
	// mtr: nh->avg += (totusec - oldavg + .0) / nh->returned;
	// C computes the whole running-mean sum in double, then truncates toward
	// zero on assignment to the int field. We must truncate at the same point:
	// compute oldAvg + delta/returned in float64 and truncate once, otherwise a
	// negative fractional delta flips the last displayed digit (~7% of hops).
	h.Avg = int(float64(oldAvg) + float64(rtt-oldAvg)/float64(h.Returned))
	// mtr: nh->ssd += (totusec - oldavg + .0) * (totusec - nh->avg);
	h.SSD += int64(float64(rtt-oldAvg) * float64(rtt-h.Avg))

	// Step 7: Average jitter via Welford (mtr lines 311-313).
	oldJAvg := h.JAvg
	h.JAvg = oldJAvg + (h.Jitter-oldJAvg)/h.Returned

	// Step 8: RFC 1889 interarrival jitter (mtr lines 315-316).
	// mtr: nh->jinta += nh->jitter - ((nh->jinta + 8) >> 4);
	h.JInta += h.Jitter - ((h.JInta + 8) >> 4)

	// Step 9: Geometric mean via iterative power (mtr lines 318-323).
	if h.Returned > 1 {
		// mtr: gmean = pow(gmean, (returned-1)/returned) * pow(totusec, 1/returned)
		n := float64(h.Returned)
		h.GMean = int(math.Pow(float64(h.GMean), (n-1.0)/n) *
			math.Pow(float64(rtt), 1.0/n))
	}

	// Step 10: Reset transit/sent/up (mtr lines 325-327).
	h.Sent = 0
	h.Up = 1
	h.Transit = 0

	// Save in ring buffer.
	idx := (h.SavedSeqOff + h.Returned - 1) % SavedPings
	h.Saved[idx] = rtt
}

// AddSent records that a probe was transmitted.
// Mirrors mtr's net_send_query: xmit++, transit=1.
func (h *HopStats) AddSent() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Xmit++
	h.Transit = 1
}

// Loss returns the loss percentage * 1000 (to match mtr's net_loss).
// mtr formula: 1000 * (100 - (100.0 * returned / (xmit - transit)))
func (h *HopStats) Loss() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	completed := h.Xmit - h.Transit
	if completed == 0 {
		return 0
	}
	return int(1000.0 * (100.0 - (100.0 * float64(h.Returned) / float64(completed))))
}

// Drop returns the number of dropped packets.
// mtr formula: (xmit - transit) - returned
func (h *HopStats) Drop() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return (h.Xmit - h.Transit) - h.Returned
}

// StDev returns the standard deviation in microseconds.
// mtr formula: sqrt(ssd / (returned - 1.0))
func (h *HopStats) StDev() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Returned < 2 {
		return 0
	}
	return int(math.Sqrt(float64(h.SSD) / (float64(h.Returned) - 1.0)))
}

// Snapshot returns a read-consistent copy of the stats for display.
func (h *HopStats) Snapshot() HopSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	best := h.Best
	if h.Returned == 0 {
		best = 0
	}
	return HopSnapshot{
		Addr:     h.Addr,
		Addrs:    append([]net.IP(nil), h.Addrs...),
		Err:      h.Err,
		Xmit:     h.Xmit,
		Returned: h.Returned,
		Transit:  h.Transit,
		Last:     h.Last,
		Best:     best,
		Worst:    h.Worst,
		Avg:      h.Avg,
		GMean:    h.GMean,
		StDev:    int(math.Sqrt(float64(h.SSD) / math.Max(float64(h.Returned)-1.0, 1.0))),
		Jitter:   h.Jitter,
		JAvg:     h.JAvg,
		JWorst:   h.JWorst,
		JInta:    h.JInta,
		Mpls:     h.Mpls,
	}
}

// HopSnapshot is a point-in-time read of hop data (no mutex needed).
type HopSnapshot struct {
	Addr     net.IP
	Addrs    []net.IP
	Err      int
	Xmit     int
	Returned int
	Transit  int
	Last     int
	Best     int
	Worst    int
	Avg      int
	GMean    int
	StDev    int
	Jitter   int
	JAvg     int
	JWorst   int
	JInta    int
	Mpls     MPLS
}
