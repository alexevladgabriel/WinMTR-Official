package trace

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	mplspkg "github.com/WinMTR/WinMTR-Official/internal/mpls"
)

// Engine manages the trace loop, sending probes and collecting stats.
// Mirrors mtr's net_send_batch() logic: probes cycle through fstTTL..maxTTL,
// restarting when the destination is reached, maxUnknown consecutive timeouts
// occur, or maxTTL is hit.
type Engine struct {
	cfg    *Config
	hops   [MaxHost]*HopStats
	prober Prober
}

// NewEngine creates a trace engine with the given config.
func NewEngine(cfg *Config) *Engine {
	e := &Engine{
		cfg: cfg,
	}
	for i := range e.hops {
		e.hops[i] = NewHopStats()
	}
	return e
}

// Run performs the trace. Blocks until complete or ctx is cancelled.
// Mirrors mtr's batch probing: each cycle sends one probe per TTL from fstTTL
// up to maxTTL, stopping early when the destination is found or maxUnknown
// consecutive non-responding hops are seen.
func (e *Engine) Run(ctx context.Context) {
	prober, err := e.createProber()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtr: %v\n", err)
		return
	}
	e.prober = prober
	defer prober.Close()

	dst := e.cfg.RemoteAddr
	timeout := time.Duration(e.cfg.ProbeTimeout) * time.Microsecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	interval := time.Duration(float64(time.Second) * e.cfg.WaitTime)

	seq := MinSequence

cycleLoop:
	for cycle := 0; cycle < e.cfg.MaxPing; cycle++ {
		// Check for cancellation before starting a new cycle.
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Each cycle probes all TTLs from fstTTL to maxTTL (like mtr's batch).
		// We stop early if: destination reached, or maxUnknown consecutive unknowns.
		nUnknown := 0
		reachedDst := false

		for ttl := e.cfg.FstTTL; ttl <= e.cfg.MaxTTL; ttl++ {
			// Check context cancellation between TTL probes.
			if ctx.Err() != nil {
				return
			}

			hop := e.hops[ttl-1]
			hop.AddSent()

			result, err := prober.Send(dst, ttl, timeout, seq)
			seq++
			if seq >= MaxSequence {
				seq = MinSequence
			}

			if err != nil {
				nUnknown++
				if nUnknown > e.cfg.MaxUnknown {
					break
				}
				continue
			}

			if result.Err == -1 {
				// Timeout, no response — count as unknown.
				nUnknown++
				if nUnknown > e.cfg.MaxUnknown {
					break
				}
				continue
			}

			// Got a response — reset unknown counter.
			nUnknown = 0

			rttUS := int(result.RTT.Microseconds())
			hop.mu.Lock()
			hop.Addr = result.Addr
			// Track ECMP paths.
			if result.Addr != nil {
				found := false
				for _, a := range hop.Addrs {
					if a.Equal(result.Addr) {
						found = true
						break
					}
				}
				if !found && len(hop.Addrs) < MaxPath {
					hop.Addrs = append(hop.Addrs, result.Addr)
				}
			}
			hop.Err = result.Err
			hop.mu.Unlock()

			hop.AddResult(rttUS)

			// Parse MPLS extensions if enabled.
			if e.cfg.EnableMPLS && len(result.ICMPExt) > 0 {
				if stack := mplspkg.ParseICMPExtension(result.ICMPExt); stack != nil {
					hop.mu.Lock()
					hop.Mpls.Labels = nil
					for _, l := range stack.Labels {
						hop.Mpls.Labels = append(hop.Mpls.Labels, MPLSLabel{
							Label: l.Label,
							TC:    l.TC,
							S:     l.S,
							TTL:   l.TTL,
						})
					}
					hop.mu.Unlock()
				}
			}

			// Check if we reached the destination.
			if result.Reached {
				reachedDst = true
				break
			}
		}

		// Break out of the cycle loop early when the destination was reached
		// and we are not forced to run all cycles.
		if reachedDst && !e.cfg.ForceMaxPing && e.cfg.Interactive {
			break cycleLoop
		}

		// Wait between cycles (except after the last one).
		if cycle < e.cfg.MaxPing-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return
			}
		}
	}

	// Grace period to allow late responses.
	if e.cfg.GraceTime > 0 {
		select {
		case <-time.After(time.Duration(float64(time.Second) * e.cfg.GraceTime)):
		case <-ctx.Done():
		}
	}
}

// netMax returns the highest hop to display, matching mtr's net_max().
// It scans from fstTTL to maxTTL and returns the index of the last known hop
// or the destination, whichever comes first.
func (e *Engine) netMax() int {
	max := e.cfg.FstTTL
	for i := e.cfg.FstTTL - 1; i < e.cfg.MaxTTL; i++ {
		e.hops[i].mu.RLock()
		addr := e.hops[i].Addr
		err := e.hops[i].Err
		xmit := e.hops[i].Xmit
		e.hops[i].mu.RUnlock()

		if xmit > 0 {
			max = i + 1
		}

		if addr != nil && addr.Equal(e.cfg.RemoteAddr) {
			return i + 1
		}
		if err != 0 {
			return i + 1
		}
	}
	return max
}

// Snapshots returns a consistent snapshot of all hops up to the display max.
func (e *Engine) Snapshots() []HopSnapshot {
	max := e.netMax()

	snaps := make([]HopSnapshot, max)
	for i := e.cfg.FstTTL - 1; i < max; i++ {
		snaps[i] = e.hops[i].Snapshot()
	}
	return snaps
}

// MaxHop returns the highest hop to display.
func (e *Engine) MaxHop() int {
	return e.netMax()
}

func (e *Engine) createProber() (Prober, error) {
	switch e.cfg.Protocol {
	case ProtoICMP:
		return NewICMPProber(e.cfg)
	case ProtoTCP:
		return NewTCPProber(e.cfg), nil
	case ProtoUDP:
		return NewUDPProber(e.cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol")
	}
}

func extractIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

// ResolveHopName returns the display name for a hop address.
func ResolveHopName(cfg *Config, addr net.IP) string {
	if addr == nil {
		return "???"
	}
	return addr.String()
}
