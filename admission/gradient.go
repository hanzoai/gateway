// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Package admission implements clean-room adaptive concurrency admission control
// for Hanzo Gateway endpoints per HIP-1348 §1.
//
// The controller uses an RTT-gradient / queueing-slope algorithm inspired by
// Netflix's concurrency-limits design: it maintains a rotating sliding window
// of minimum observed round-trip time (minRTT), compares smoothed current
// latency against that baseline, shrinks the concurrency budget proportionally
// when queue build-up or upstream tail latency appears, and grows
// conservatively when latency remains low under real utilization.
//
// When concurrency budget is exhausted, requests are shed immediately at the
// edge and attributed with explicit "budget_exhausted" / "admission_shed"
// decision metadata across HIP-1348 §1 layers (tenant_ledger, ai_gateway,
// worker, durable_object, upstream_provider).
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Layer identifies the HIP-1348 §1 overload / spend-limit attribution tier.
type Layer string

const (
	LayerTenantLedger     Layer = "tenant_ledger"
	LayerAIGateway        Layer = "ai_gateway"
	LayerWorker           Layer = "worker"
	LayerDurableObject    Layer = "durable_object"
	LayerUpstreamProvider Layer = "upstream_provider"
)

// Decision and error attribution codes emitted when admission sheds load.
const (
	CodeBudgetExhausted = "budget_exhausted"
	CodeAdmissionShed   = "admission_shed"
	CodeAdmitted        = "admitted"
)

// AllLayers returns the canonical HIP-1348 §1 attribution layers.
func AllLayers() []Layer {
	return []Layer{
		LayerTenantLedger,
		LayerAIGateway,
		LayerWorker,
		LayerDurableObject,
		LayerUpstreamProvider,
	}
}

// ValidLayer reports whether l is one of the canonical HIP-1348 §1 layers.
func ValidLayer(l Layer) bool {
	switch l {
	case LayerTenantLedger, LayerAIGateway, LayerWorker, LayerDurableObject, LayerUpstreamProvider:
		return true
	default:
		return false
	}
}

// Config configures a GradientLimiter.
type Config struct {
	// Layer names the HIP-1348 §1 attribution layer (default: ai_gateway).
	Layer Layer
	// Endpoint optionally identifies the route or upstream pool in metrics.
	Endpoint string

	// InitialLimit is the starting concurrency ceiling (default: 20).
	InitialLimit int
	// MinLimit is the lowest concurrency ceiling allowed (default: 4).
	MinLimit int
	// MaxLimit is the highest concurrency ceiling allowed (default: 200).
	MaxLimit int

	// MinRTTWindow is the rotating baseline window for minRTT tracking (default: 30s).
	MinRTTWindow time.Duration
	// WindowDuration is the minimum interval between limit adjustments (default: 50ms).
	WindowDuration time.Duration
	// WindowMinSamples is the minimum completed samples per adjustment window (default: 8).
	WindowMinSamples int
	// MinRTTFloor prevents division by near-zero durations (default: 100µs).
	MinRTTFloor time.Duration

	// Tolerance is the allowable shortRTT/minRTT multiplier before congestion
	// shrinking triggers (default: 1.5; must be >= 1.0).
	Tolerance float64
	// MinGradient bounds the minimum single-step gradient factor (default: 0.5).
	MinGradient float64
	// Smoothing controls EWMA damping of limit updates in (0, 1] (default: 0.30).
	Smoothing float64
	// RTTAlpha controls EWMA reactivity for shortRTT in (0, 1] (default: 0.25).
	RTTAlpha float64
	// LongRTTAlpha controls slow baseline tracking for diagnostics in (0, 1] (default: 0.05).
	LongRTTAlpha float64
	// AppLimitedRatio skips growth when observed maxInFlight < limit*ratio (default: 0.5).
	AppLimitedRatio float64
	// CongestionBackoff scales the limit down on explicit upstream drop/overload
	// signals (e.g., 429/503/timeout) in (0, 1] (default: 0.85).
	CongestionBackoff float64
	// MaxGrowthPerWindow caps additive concurrency growth per healthy window (default: 2.0).
	MaxGrowthPerWindow float64

	// RejectHTTPStatus sets the HTTP status written by Middleware on shed (default: 429).
	RejectHTTPStatus int
	// RetryAfter advises callers how long to wait before retrying (default: 100ms).
	RetryAfter time.Duration

	// Now overrides the clock for deterministic testing (default: time.Now).
	Now func() time.Time
	// OnDecision receives emitted admission decisions (all shed events, and
	// admitted events when EmitAdmittedDecisions is true).
	OnDecision func(Decision)
	// EmitAdmittedDecisions enables OnDecision callbacks on allowed requests.
	EmitAdmittedDecisions bool
}

// DefaultConfig returns production-safe defaults for gateway admission control.
func DefaultConfig() Config {
	return Config{
		Layer:              LayerAIGateway,
		InitialLimit:       20,
		MinLimit:           4,
		MaxLimit:           200,
		MinRTTWindow:       30 * time.Second,
		WindowDuration:     50 * time.Millisecond,
		WindowMinSamples:   8,
		MinRTTFloor:        100 * time.Microsecond,
		Tolerance:          1.5,
		MinGradient:        0.5,
		Smoothing:          0.30,
		RTTAlpha:           0.25,
		LongRTTAlpha:       0.05,
		AppLimitedRatio:    0.50,
		CongestionBackoff:  0.85,
		MaxGrowthPerWindow: 2.0,
		RejectHTTPStatus:   http.StatusTooManyRequests,
		RetryAfter:         100 * time.Millisecond,
	}
}

func (c Config) normalized() (Config, error) {
	d := DefaultConfig()
	if c.Layer == "" {
		c.Layer = d.Layer
	}
	if !ValidLayer(c.Layer) {
		return Config{}, fmt.Errorf("admission: unknown layer %q", c.Layer)
	}
	if c.MinLimit <= 0 {
		c.MinLimit = d.MinLimit
	}
	if c.MaxLimit <= 0 {
		c.MaxLimit = d.MaxLimit
	}
	if c.MaxLimit < c.MinLimit {
		return Config{}, fmt.Errorf("admission: MaxLimit (%d) < MinLimit (%d)", c.MaxLimit, c.MinLimit)
	}
	if c.InitialLimit <= 0 {
		c.InitialLimit = d.InitialLimit
	}
	if c.InitialLimit < c.MinLimit {
		c.InitialLimit = c.MinLimit
	}
	if c.InitialLimit > c.MaxLimit {
		c.InitialLimit = c.MaxLimit
	}
	if c.MinRTTWindow < 0 {
		return Config{}, fmt.Errorf("admission: negative MinRTTWindow %s", c.MinRTTWindow)
	}
	if c.MinRTTWindow == 0 {
		c.MinRTTWindow = d.MinRTTWindow
	}
	if c.WindowDuration < 0 {
		return Config{}, fmt.Errorf("admission: negative WindowDuration %s", c.WindowDuration)
	}
	if c.WindowMinSamples <= 0 {
		c.WindowMinSamples = d.WindowMinSamples
	}
	if c.MinRTTFloor <= 0 {
		c.MinRTTFloor = d.MinRTTFloor
	}
	if c.Tolerance == 0 {
		c.Tolerance = d.Tolerance
	}
	if c.Tolerance < 1.0 {
		return Config{}, fmt.Errorf("admission: Tolerance (%v) must be >= 1.0", c.Tolerance)
	}
	if c.MinGradient == 0 {
		c.MinGradient = d.MinGradient
	}
	if c.MinGradient <= 0 || c.MinGradient > 1.0 {
		return Config{}, fmt.Errorf("admission: MinGradient (%v) must be in (0, 1]", c.MinGradient)
	}
	if c.Smoothing == 0 {
		c.Smoothing = d.Smoothing
	}
	if c.Smoothing <= 0 || c.Smoothing > 1.0 {
		return Config{}, fmt.Errorf("admission: Smoothing (%v) must be in (0, 1]", c.Smoothing)
	}
	if c.RTTAlpha == 0 {
		c.RTTAlpha = d.RTTAlpha
	}
	if c.RTTAlpha <= 0 || c.RTTAlpha > 1.0 {
		return Config{}, fmt.Errorf("admission: RTTAlpha (%v) must be in (0, 1]", c.RTTAlpha)
	}
	if c.LongRTTAlpha == 0 {
		c.LongRTTAlpha = d.LongRTTAlpha
	}
	if c.LongRTTAlpha <= 0 || c.LongRTTAlpha > 1.0 {
		return Config{}, fmt.Errorf("admission: LongRTTAlpha (%v) must be in (0, 1]", c.LongRTTAlpha)
	}
	if c.AppLimitedRatio < 0 || c.AppLimitedRatio > 1.0 {
		return Config{}, fmt.Errorf("admission: AppLimitedRatio (%v) must be in [0, 1]", c.AppLimitedRatio)
	}
	if c.AppLimitedRatio == 0 {
		c.AppLimitedRatio = d.AppLimitedRatio
	}
	if c.CongestionBackoff == 0 {
		c.CongestionBackoff = d.CongestionBackoff
	}
	if c.CongestionBackoff <= 0 || c.CongestionBackoff > 1.0 {
		return Config{}, fmt.Errorf("admission: CongestionBackoff (%v) must be in (0, 1]", c.CongestionBackoff)
	}
	if c.MaxGrowthPerWindow <= 0 {
		c.MaxGrowthPerWindow = d.MaxGrowthPerWindow
	}
	if c.RejectHTTPStatus == 0 {
		c.RejectHTTPStatus = d.RejectHTTPStatus
	}
	if c.RetryAfter <= 0 {
		c.RetryAfter = d.RetryAfter
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

// Decision captures a single admission outcome and attribution metadata.
type Decision struct {
	Allowed    bool          `json:"allowed"`
	Code       string        `json:"code"`
	Event      string        `json:"event"`
	Layer      Layer         `json:"layer"`
	Endpoint   string        `json:"endpoint,omitempty"`
	InFlight   int64         `json:"in_flight"`
	Limit      int           `json:"limit"`
	MinRTT     time.Duration `json:"min_rtt_ns,omitempty"`
	ShortRTT   time.Duration `json:"short_rtt_ns,omitempty"`
	Gradient   float64       `json:"gradient,omitempty"`
	RetryAfter time.Duration `json:"retry_after_ns,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// Rejection is returned when admission control sheds a request due to
// concurrency budget exhaustion.
type Rejection struct {
	Code       string        `json:"error"`
	Event      string        `json:"event"`
	Layer      Layer         `json:"layer"`
	Endpoint   string        `json:"endpoint,omitempty"`
	InFlight   int64         `json:"in_flight"`
	Limit      int           `json:"limit"`
	RetryAfter time.Duration `json:"retry_after_ns"`
	Status     int           `json:"status"`
}

// Error implements the error interface with explicit HIP-1348 layer attribution.
func (r *Rejection) Error() string {
	if r == nil {
		return ""
	}
	if r.Endpoint != "" {
		return fmt.Sprintf("%s (%s): layer=%s endpoint=%s in_flight=%d limit=%d",
			r.Code, r.Event, r.Layer, r.Endpoint, r.InFlight, r.Limit)
	}
	return fmt.Sprintf("%s (%s): layer=%s in_flight=%d limit=%d",
		r.Code, r.Event, r.Layer, r.InFlight, r.Limit)
}

// HTTPStatus returns the HTTP status code appropriate for this rejection.
func (r *Rejection) HTTPStatus() int {
	if r == nil || r.Status == 0 {
		return http.StatusTooManyRequests
	}
	return r.Status
}

// Snapshot holds a point-in-time view of limiter state and metrics.
type Snapshot struct {
	Layer                Layer
	Endpoint             string
	Limit                int
	EstimatedLimit       float64
	InFlight             int64
	MaxInFlightObserved  int64
	MinRTT               time.Duration
	ShortRTT             time.Duration
	LongRTT              time.Duration
	Gradient             float64
	AdmittedTotal        uint64
	BudgetExhaustedTotal uint64
	AdmissionShedTotal   uint64
	SuccessTotal         uint64
	DroppedTotal         uint64
	IgnoredTotal         uint64
	LimitUpdates         uint64
	LastDecision         *Decision
}

// Lease represents an admitted in-flight request slot. Exactly one terminal
// method (Success, Dropped, or Ignore) should be invoked when the request ends.
// Subsequent terminal calls are safe no-ops.
type Lease struct {
	limiter  *GradientLimiter
	started  time.Time
	inFlight int64
	done     atomic.Bool
}

// Success records a healthy completion and updates the RTT gradient controller.
func (l *Lease) Success() {
	l.finish(false, false)
}

// Dropped records an upstream overload/failure signal (e.g., 429, 503, timeout)
// and triggers congestion backoff without polluting minRTT.
func (l *Lease) Dropped() {
	l.finish(true, false)
}

// Ignore releases the concurrency slot without affecting RTT or limit state
// (e.g., local client validation errors or pre-upstream cancellations).
func (l *Lease) Ignore() {
	l.finish(false, true)
}

func (l *Lease) finish(dropped, ignore bool) {
	if l == nil || !l.done.CompareAndSwap(false, true) {
		return
	}
	l.limiter.inFlight.Add(-1)
	if ignore {
		l.limiter.ignoredTotal.Add(1)
		return
	}
	if dropped {
		l.limiter.droppedTotal.Add(1)
	} else {
		l.limiter.successTotal.Add(1)
	}
	rtt := l.limiter.cfg.Now().Sub(l.started)
	l.limiter.Observe(rtt, l.inFlight, dropped)
}

// GradientLimiter controls request concurrency using an RTT-gradient controller.
type GradientLimiter struct {
	cfg Config

	inFlight          atomic.Int64
	limit             atomic.Int64
	windowMaxInFlight atomic.Int64

	admittedTotal        atomic.Uint64
	budgetExhaustedTotal atomic.Uint64
	admissionShedTotal   atomic.Uint64
	successTotal         atomic.Uint64
	droppedTotal         atomic.Uint64
	ignoredTotal         atomic.Uint64
	limitUpdates         atomic.Uint64

	mu             sync.Mutex
	estimatedLimit float64
	prevMinRTT     time.Duration
	currMinRTT     time.Duration
	minBucketStart time.Time
	shortRTT       float64
	longRTT        float64
	lastGradient   float64
	maxInFlightObs int64

	winStart  time.Time
	winSumRTT float64
	winCount  int
	winDrops  int

	lastDecision *Decision
}

// NewGradientLimiter constructs an adaptive gradient concurrency limiter.
func NewGradientLimiter(cfg Config) (*GradientLimiter, error) {
	norm, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	g := &GradientLimiter{
		cfg:            norm,
		estimatedLimit: float64(norm.InitialLimit),
		lastGradient:   1.0,
		winStart:       norm.Now(),
	}
	g.limit.Store(int64(norm.InitialLimit))
	return g, nil
}

// Limit returns the active concurrency ceiling.
func (g *GradientLimiter) Limit() int {
	return int(g.limit.Load())
}

// InFlight returns the current number of admitted in-flight operations.
func (g *GradientLimiter) InFlight() int64 {
	return g.inFlight.Load()
}

// TryAcquire attempts to reserve one concurrency slot without blocking.
// When in_flight >= limit, it immediately sheds the request and returns a
// *Rejection with CodeBudgetExhausted ("budget_exhausted") and Event
// CodeAdmissionShed ("admission_shed").
func (g *GradientLimiter) TryAcquire() (*Lease, error) {
	lease, dec := g.TryAcquireDecision()
	if !dec.Allowed {
		return nil, &Rejection{
			Code:       dec.Code,
			Event:      dec.Event,
			Layer:      dec.Layer,
			Endpoint:   dec.Endpoint,
			InFlight:   dec.InFlight,
			Limit:      dec.Limit,
			RetryAfter: dec.RetryAfter,
			Status:     g.cfg.RejectHTTPStatus,
		}
	}
	return lease, nil
}

// TryAcquireDecision attempts to reserve one concurrency slot and returns both
// the Lease (nil if shed) and the full Decision record.
func (g *GradientLimiter) TryAcquireDecision() (*Lease, Decision) {
	now := g.cfg.Now()
	for {
		cur := g.inFlight.Load()
		lim := g.limit.Load()
		if cur >= lim {
			g.budgetExhaustedTotal.Add(1)
			g.admissionShedTotal.Add(1)

			g.mu.Lock()
			minRTT := g.effectiveMinRTTLocked()
			shortRTT := time.Duration(math.Round(g.shortRTT))
			grad := g.lastGradient
			dec := Decision{
				Allowed:    false,
				Code:       CodeBudgetExhausted,
				Event:      CodeAdmissionShed,
				Layer:      g.cfg.Layer,
				Endpoint:   g.cfg.Endpoint,
				InFlight:   cur,
				Limit:      int(lim),
				MinRTT:     minRTT,
				ShortRTT:   shortRTT,
				Gradient:   grad,
				RetryAfter: g.cfg.RetryAfter,
				Timestamp:  now,
			}
			cp := dec
			g.lastDecision = &cp
			g.mu.Unlock()

			if g.cfg.OnDecision != nil {
				g.cfg.OnDecision(dec)
			}
			return nil, dec
		}
		if g.inFlight.CompareAndSwap(cur, cur+1) {
			nextInFlight := cur + 1
			g.admittedTotal.Add(1)
			g.recordWindowMaxInFlight(nextInFlight)

			dec := Decision{
				Allowed:   true,
				Code:      CodeAdmitted,
				Event:     CodeAdmitted,
				Layer:     g.cfg.Layer,
				Endpoint:  g.cfg.Endpoint,
				InFlight:  nextInFlight,
				Limit:     int(lim),
				Timestamp: now,
			}
			if g.cfg.EmitAdmittedDecisions && g.cfg.OnDecision != nil {
				g.mu.Lock()
				dec.MinRTT = g.effectiveMinRTTLocked()
				dec.ShortRTT = time.Duration(math.Round(g.shortRTT))
				dec.Gradient = g.lastGradient
				g.mu.Unlock()
				g.cfg.OnDecision(dec)
			}
			return &Lease{
				limiter:  g,
				started:  now,
				inFlight: nextInFlight,
			}, dec
		}
	}
}

// Acquire checks ctx cancellation and delegates to TryAcquire. Because this is
// load-shedding admission control, saturated slots fail immediately rather than
// queueing.
func (g *GradientLimiter) Acquire(ctx context.Context) (*Lease, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return g.TryAcquire()
}

func (g *GradientLimiter) recordWindowMaxInFlight(v int64) {
	for {
		prev := g.windowMaxInFlight.Load()
		if v <= prev || g.windowMaxInFlight.CompareAndSwap(prev, v) {
			return
		}
	}
}

// Observe feeds a completed sample (rtt, inFlight, dropped) directly into the
// gradient controller. Callers using TryAcquire/Lease do not need to call
// Observe manually; it is exposed for deterministic verification and probing.
func (g *GradientLimiter) Observe(rtt time.Duration, inFlight int64, dropped bool) {
	now := g.cfg.Now()
	if rtt < g.cfg.MinRTTFloor {
		rtt = g.cfg.MinRTTFloor
	}
	g.recordWindowMaxInFlight(inFlight)

	g.mu.Lock()
	defer g.mu.Unlock()

	if inFlight > g.maxInFlightObs {
		g.maxInFlightObs = inFlight
	}

	rttFloat := float64(rtt)
	if !dropped {
		g.updateMinRTTLocked(now, rtt)
		if g.shortRTT == 0 {
			g.shortRTT = rttFloat
		} else {
			g.shortRTT = (1.0-g.cfg.RTTAlpha)*g.shortRTT + g.cfg.RTTAlpha*rttFloat
		}
		if g.longRTT == 0 {
			g.longRTT = rttFloat
		} else {
			g.longRTT = (1.0-g.cfg.LongRTTAlpha)*g.longRTT + g.cfg.LongRTTAlpha*rttFloat
		}
	} else if g.shortRTT == 0 {
		g.shortRTT = rttFloat
	}

	g.winSumRTT += rttFloat
	g.winCount++
	if dropped {
		g.winDrops++
	}

	elapsed := now.Sub(g.winStart)
	readyByCount := g.winCount >= g.cfg.WindowMinSamples && elapsed >= g.cfg.WindowDuration
	readyByTimeout := g.winCount > 0 && g.cfg.WindowDuration > 0 && elapsed >= 2*g.cfg.WindowDuration
	if readyByCount || readyByTimeout {
		g.updateLimitLocked(now)
	}
}

func (g *GradientLimiter) updateMinRTTLocked(now time.Time, rtt time.Duration) {
	half := g.cfg.MinRTTWindow / 2
	if g.minBucketStart.IsZero() {
		g.minBucketStart = now
		g.currMinRTT = rtt
		return
	}
	if half <= 0 {
		if g.currMinRTT == 0 || rtt < g.currMinRTT {
			g.currMinRTT = rtt
		}
		return
	}
	elapsed := now.Sub(g.minBucketStart)
	if elapsed >= 2*half {
		// Entire rotating window expired; reset cleanly to current baseline.
		g.prevMinRTT = 0
		g.currMinRTT = rtt
		g.minBucketStart = now
		return
	}
	if elapsed >= half {
		// Advance half-window: retain previous half as prevMinRTT so minRTT
		// never spikes abruptly at rotation boundaries.
		g.prevMinRTT = g.currMinRTT
		g.currMinRTT = rtt
		g.minBucketStart = now
		return
	}
	if g.currMinRTT == 0 || rtt < g.currMinRTT {
		g.currMinRTT = rtt
	}
}

func (g *GradientLimiter) effectiveMinRTTLocked() time.Duration {
	if g.prevMinRTT > 0 && g.currMinRTT > 0 {
		if g.prevMinRTT < g.currMinRTT {
			return g.prevMinRTT
		}
		return g.currMinRTT
	}
	if g.currMinRTT > 0 {
		return g.currMinRTT
	}
	return g.prevMinRTT
}

func (g *GradientLimiter) updateLimitLocked(now time.Time) {
	maxInFlight := g.windowMaxInFlight.Swap(g.inFlight.Load())
	effectiveRTT := g.shortRTT
	if effectiveRTT <= 0 && g.winCount > 0 {
		effectiveRTT = g.winSumRTT / float64(g.winCount)
	}

	minRTT := g.effectiveMinRTTLocked()
	if minRTT <= 0 {
		minRTT = g.cfg.MinRTTFloor
	}
	baseline := math.Max(float64(minRTT), float64(g.cfg.MinRTTFloor))
	if effectiveRTT < baseline {
		effectiveRTT = baseline
	}

	rawGradient := (g.cfg.Tolerance * baseline) / effectiveRTT
	gradient := math.Min(1.0, math.Max(g.cfg.MinGradient, rawGradient))
	g.lastGradient = gradient

	curEst := g.estimatedLimit
	var nextEst float64

	switch {
	case g.winDrops > 0:
		dropRatio := float64(g.winDrops) / float64(g.winCount)
		backoff := 1.0 - (1.0-g.cfg.CongestionBackoff)*math.Min(1.0, 2.0*dropRatio)
		target := curEst * gradient * backoff
		nextEst = (1.0-g.cfg.Smoothing)*curEst + g.cfg.Smoothing*target
	case gradient < 1.0:
		// Queue build-up or slow upstream tails: shrink proportionally toward target.
		target := curEst * gradient
		shrinkAlpha := math.Min(1.0, g.cfg.Smoothing*1.25)
		nextEst = (1.0-shrinkAlpha)*curEst + shrinkAlpha*target
	default:
		// Healthy low latency: grow conservatively only when traffic is actually
		// exercising the current concurrency ceiling (app-limited guard).
		if float64(maxInFlight) >= curEst*g.cfg.AppLimitedRatio {
			growth := math.Min(g.cfg.MaxGrowthPerWindow, math.Max(1.0, math.Sqrt(curEst)*0.35))
			target := curEst + growth
			growAlpha := g.cfg.Smoothing * 0.75
			nextEst = (1.0-growAlpha)*curEst + growAlpha*target
		} else {
			nextEst = curEst
		}
	}

	minF := float64(g.cfg.MinLimit)
	maxF := float64(g.cfg.MaxLimit)
	if nextEst < minF {
		nextEst = minF
	} else if nextEst > maxF {
		nextEst = maxF
	}
	g.estimatedLimit = nextEst

	rounded := int(math.Round(nextEst))
	if rounded < g.cfg.MinLimit {
		rounded = g.cfg.MinLimit
	} else if rounded > g.cfg.MaxLimit {
		rounded = g.cfg.MaxLimit
	}
	g.limit.Store(int64(rounded))
	g.limitUpdates.Add(1)

	g.winStart = now
	g.winSumRTT = 0
	g.winCount = 0
	g.winDrops = 0
}

// Snapshot returns a thread-safe copy of the limiter's current state and metrics.
func (g *GradientLimiter) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()

	var lastCopy *Decision
	if g.lastDecision != nil {
		cp := *g.lastDecision
		lastCopy = &cp
	}
	return Snapshot{
		Layer:                g.cfg.Layer,
		Endpoint:             g.cfg.Endpoint,
		Limit:                int(g.limit.Load()),
		EstimatedLimit:       g.estimatedLimit,
		InFlight:             g.inFlight.Load(),
		MaxInFlightObserved:  g.maxInFlightObs,
		MinRTT:               g.effectiveMinRTTLocked(),
		ShortRTT:             time.Duration(math.Round(g.shortRTT)),
		LongRTT:              time.Duration(math.Round(g.longRTT)),
		Gradient:             g.lastGradient,
		AdmittedTotal:        g.admittedTotal.Load(),
		BudgetExhaustedTotal: g.budgetExhaustedTotal.Load(),
		AdmissionShedTotal:   g.admissionShedTotal.Load(),
		SuccessTotal:         g.successTotal.Load(),
		DroppedTotal:         g.droppedTotal.Load(),
		IgnoredTotal:         g.ignoredTotal.Load(),
		LimitUpdates:         g.limitUpdates.Load(),
		LastDecision:         lastCopy,
	}
}

// Collector returns a prometheus.Collector exposing explicit budget_exhausted,
// admission_shed, layer, in_flight, limit, and RTT gradient gauges/counters.
func (g *GradientLimiter) Collector() prometheus.Collector {
	return &limiterCollector{limiter: g}
}

type limiterCollector struct {
	limiter *GradientLimiter
}

var (
	descDecisions = prometheus.NewDesc(
		"gateway_admission_decisions_total",
		"Total adaptive concurrency admission decisions attributed by layer, code, and event.",
		[]string{"layer", "endpoint", "code", "event"},
		nil,
	)
	descBudgetExhausted = prometheus.NewDesc(
		"gateway_admission_budget_exhausted_total",
		"Total requests rejected due to concurrency budget_exhausted.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descAdmissionShed = prometheus.NewDesc(
		"gateway_admission_shed_total",
		"Total requests shed by adaptive concurrency admission control.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descInFlight = prometheus.NewDesc(
		"gateway_admission_in_flight",
		"Current number of admitted in-flight requests.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descLimit = prometheus.NewDesc(
		"gateway_admission_limit",
		"Current adaptive concurrency limit.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descMinRTT = prometheus.NewDesc(
		"gateway_admission_min_rtt_seconds",
		"Current windowed minimum observed RTT in seconds.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descShortRTT = prometheus.NewDesc(
		"gateway_admission_short_rtt_seconds",
		"Current EWMA short-window RTT in seconds.",
		[]string{"layer", "endpoint"},
		nil,
	)
	descGradient = prometheus.NewDesc(
		"gateway_admission_gradient",
		"Most recent RTT gradient ratio used to update the concurrency limit.",
		[]string{"layer", "endpoint"},
		nil,
	)
)

func (c *limiterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descDecisions
	ch <- descBudgetExhausted
	ch <- descAdmissionShed
	ch <- descInFlight
	ch <- descLimit
	ch <- descMinRTT
	ch <- descShortRTT
	ch <- descGradient
}

func (c *limiterCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.limiter.Snapshot()
	layer := string(s.Layer)
	ep := s.Endpoint

	ch <- prometheus.MustNewConstMetric(descDecisions, prometheus.CounterValue,
		float64(s.AdmittedTotal), layer, ep, CodeAdmitted, CodeAdmitted)
	ch <- prometheus.MustNewConstMetric(descDecisions, prometheus.CounterValue,
		float64(s.BudgetExhaustedTotal), layer, ep, CodeBudgetExhausted, CodeAdmissionShed)
	ch <- prometheus.MustNewConstMetric(descBudgetExhausted, prometheus.CounterValue,
		float64(s.BudgetExhaustedTotal), layer, ep)
	ch <- prometheus.MustNewConstMetric(descAdmissionShed, prometheus.CounterValue,
		float64(s.AdmissionShedTotal), layer, ep)
	ch <- prometheus.MustNewConstMetric(descInFlight, prometheus.GaugeValue,
		float64(s.InFlight), layer, ep)
	ch <- prometheus.MustNewConstMetric(descLimit, prometheus.GaugeValue,
		float64(s.Limit), layer, ep)
	ch <- prometheus.MustNewConstMetric(descMinRTT, prometheus.GaugeValue,
		s.MinRTT.Seconds(), layer, ep)
	ch <- prometheus.MustNewConstMetric(descShortRTT, prometheus.GaugeValue,
		s.ShortRTT.Seconds(), layer, ep)
	ch <- prometheus.MustNewConstMetric(descGradient, prometheus.GaugeValue,
		s.Gradient, layer, ep)
}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap preserves http.ResponseController / Flusher compatibility for streaming.
func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Middleware wraps next with adaptive concurrency admission control. When
// overloaded, it emits a JSON budget_exhausted / admission_shed response with
// layer, in_flight, and limit attribution without touching upstream handlers.
func (g *GradientLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lease, err := g.TryAcquire()
		if err != nil {
			var rej *Rejection
			if errors.As(err, &rej) {
				retrySec := int(math.Ceil(rej.RetryAfter.Seconds()))
				if retrySec < 1 {
					retrySec = 1
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(retrySec))
				w.Header().Set("X-Admission-Layer", string(rej.Layer))
				w.Header().Set("X-Admission-In-Flight", strconv.FormatInt(rej.InFlight, 10))
				w.Header().Set("X-Admission-Limit", strconv.Itoa(rej.Limit))
				w.WriteHeader(rej.HTTPStatus())
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":          rej.Code,
					"code":           rej.Code,
					"event":          rej.Event,
					"layer":          rej.Layer,
					"endpoint":       rej.Endpoint,
					"in_flight":      rej.InFlight,
					"limit":          rej.Limit,
					"retry_after_ms": rej.RetryAfter.Milliseconds(),
					"message":        rej.Error(),
				})
				return
			}
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		sw := &statusCaptureWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				lease.Ignore()
				panic(rec)
			}
		}()

		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		switch {
		case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || status == http.StatusBadGateway || status == http.StatusGatewayTimeout:
			lease.Dropped()
		case status >= 400 && status < 500:
			lease.Ignore()
		default:
			lease.Success()
		}
	})
}
