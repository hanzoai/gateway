// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package admission

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestMinRTTWindowTrackingAndExpiration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lim, err := NewGradientLimiter(Config{
		Layer:            LayerAIGateway,
		InitialLimit:     20,
		MinLimit:         4,
		MaxLimit:         100,
		MinRTTWindow:     20 * time.Second,
		WindowDuration:   0,
		WindowMinSamples: 100, // isolate minRTT updates from limit adjustments
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	// Phase 1: baseline 10ms in first half-window [0s, 10s).
	lim.Observe(12*time.Millisecond, 5, false)
	lim.Observe(10*time.Millisecond, 5, false)
	if got := lim.Snapshot().MinRTT; got != 10*time.Millisecond {
		t.Fatalf("expected initial minRTT 10ms, got %s", got)
	}

	// Phase 2: advance into second half-window (11s). New samples are 25ms,
	// but prevMinRTT (10ms) keeps minRTT stable without a cliff.
	now = now.Add(11 * time.Second)
	lim.Observe(25*time.Millisecond, 5, false)
	if got := lim.Snapshot().MinRTT; got != 10*time.Millisecond {
		t.Fatalf("expected overlapping window minRTT 10ms, got %s", got)
	}

	// Phase 3: advance another half-window (total 22s > MinRTTWindow).
	// The 10ms half-window expires and baseline adapts to 25ms.
	now = now.Add(11 * time.Second)
	lim.Observe(25*time.Millisecond, 5, false)
	if got := lim.Snapshot().MinRTT; got != 25*time.Millisecond {
		t.Fatalf("expected expired window minRTT to adapt to 25ms, got %s", got)
	}
}

func TestShrinksUnderQueueBuildupAndSlowUpstream(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lim, err := NewGradientLimiter(Config{
		Layer:            LayerUpstreamProvider,
		InitialLimit:     32,
		MinLimit:         4,
		MaxLimit:         128,
		MinRTTWindow:     60 * time.Second,
		WindowDuration:   20 * time.Millisecond,
		WindowMinSamples: 5,
		Tolerance:        1.5,
		Smoothing:        0.35,
		RTTAlpha:         0.35,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	// Establish fast baseline 10ms.
	for w := 0; w < 3; w++ {
		now = now.Add(25 * time.Millisecond)
		for i := 0; i < 6; i++ {
			lim.Observe(10*time.Millisecond, 10, false)
		}
	}
	before := lim.Limit()

	// Inject queue build-up / slow upstream tails (50ms = 5x minRTT).
	for w := 0; w < 8; w++ {
		now = now.Add(25 * time.Millisecond)
		for i := 0; i < 6; i++ {
			lim.Observe(50*time.Millisecond, int64(lim.Limit()), false)
		}
	}
	snap := lim.Snapshot()
	if snap.Limit >= before {
		t.Fatalf("expected limit to shrink under 5x latency spike: before=%d after=%d", before, snap.Limit)
	}
	if snap.Limit > 12 {
		t.Fatalf("expected limit to shrink substantially under sustained queue buildup, got %d", snap.Limit)
	}
	if snap.Gradient >= 1.0 {
		t.Fatalf("expected gradient < 1.0 during slow upstream tails, got %.3f", snap.Gradient)
	}
}

func TestConservativeGrowthAndAppLimitedGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lim, err := NewGradientLimiter(Config{
		Layer:              LayerWorker,
		InitialLimit:       20,
		MinLimit:           4,
		MaxLimit:           100,
		WindowDuration:     20 * time.Millisecond,
		WindowMinSamples:   5,
		AppLimitedRatio:    0.5,
		MaxGrowthPerWindow: 2.0,
		Smoothing:          0.30,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	// App-limited traffic (inFlight=3 < 0.5*20=10): limit must NOT grow.
	for w := 0; w < 6; w++ {
		now = now.Add(25 * time.Millisecond)
		for i := 0; i < 6; i++ {
			lim.Observe(5*time.Millisecond, 3, false)
		}
	}
	if got := lim.Limit(); got != 20 {
		t.Fatalf("expected app-limited traffic to hold limit at 20, got %d", got)
	}

	// High utilization (inFlight=18 >= 0.5*limit) at low latency: grow conservatively.
	for w := 0; w < 6; w++ {
		now = now.Add(25 * time.Millisecond)
		for i := 0; i < 6; i++ {
			lim.Observe(5*time.Millisecond, int64(lim.Limit()), false)
		}
	}
	got := lim.Limit()
	if got <= 20 || got > 26 {
		t.Fatalf("expected conservative growth from 20 into (20, 26], got %d", got)
	}
}

func TestDroppedFastFailsTriggerBackoffWithoutPoisoningMinRTT(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lim, err := NewGradientLimiter(Config{
		Layer:             LayerDurableObject,
		InitialLimit:      24,
		MinLimit:          4,
		MaxLimit:          100,
		WindowDuration:    20 * time.Millisecond,
		WindowMinSamples:  5,
		CongestionBackoff: 0.75,
		Smoothing:         0.40,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	// Baseline 12ms.
	now = now.Add(25 * time.Millisecond)
	for i := 0; i < 6; i++ {
		lim.Observe(12*time.Millisecond, 12, false)
	}

	// Upstream fails fast in 500µs with 503/429 drops.
	for w := 0; w < 5; w++ {
		now = now.Add(25 * time.Millisecond)
		for i := 0; i < 6; i++ {
			lim.Observe(500*time.Microsecond, int64(lim.Limit()), true)
		}
	}
	snap := lim.Snapshot()
	if snap.MinRTT != 12*time.Millisecond {
		t.Fatalf("dropped fast-fails must not poison minRTT: want 12ms, got %s", snap.MinRTT)
	}
	if snap.Limit >= 20 {
		t.Fatalf("expected drops to shrink limit from 24, got %d", snap.Limit)
	}
}

func TestBudgetExhaustedAndAdmissionShedMetricsAndLayers(t *testing.T) {
	for _, layer := range AllLayers() {
		t.Run(string(layer), func(t *testing.T) {
			var emitted []Decision
			var mu sync.Mutex

			lim, err := NewGradientLimiter(Config{
				Layer:        layer,
				Endpoint:     "/v1/chat/completions",
				InitialLimit: 3,
				MinLimit:     1,
				MaxLimit:     16,
				OnDecision: func(d Decision) {
					mu.Lock()
					emitted = append(emitted, d)
					mu.Unlock()
				},
			})
			if err != nil {
				t.Fatalf("NewGradientLimiter: %v", err)
			}

			var leases []*Lease
			for i := 0; i < 3; i++ {
				l, err := lim.TryAcquire()
				if err != nil {
					t.Fatalf("acquire %d unexpected error: %v", i, err)
				}
				leases = append(leases, l)
			}

			// 4th request exceeds limit -> budget_exhausted / admission_shed.
			_, err = lim.TryAcquire()
			if err == nil {
				t.Fatal("expected rejection when in_flight == limit")
			}
			var rej *Rejection
			if !errors.As(err, &rej) {
				t.Fatalf("expected *Rejection error, got %T", err)
			}
			if rej.Code != CodeBudgetExhausted || rej.Event != CodeAdmissionShed {
				t.Fatalf("unexpected rejection codes: %+v", rej)
			}
			if rej.Layer != layer || rej.InFlight != 3 || rej.Limit != 3 {
				t.Fatalf("unexpected rejection attribution: %+v", rej)
			}

			// Decision sink must receive the attribution event.
			mu.Lock()
			if len(emitted) != 1 {
				mu.Unlock()
				t.Fatalf("expected 1 emitted shed decision, got %d", len(emitted))
			}
			d := emitted[0]
			mu.Unlock()
			if d.Allowed || d.Code != CodeBudgetExhausted || d.Event != CodeAdmissionShed ||
				d.Layer != layer || d.InFlight != 3 || d.Limit != 3 {
				t.Fatalf("unexpected decision payload: %+v", d)
			}

			// Prometheus registry verification.
			reg := prometheus.NewRegistry()
			if err := reg.Register(lim.Collector()); err != nil {
				t.Fatalf("register collector: %v", err)
			}
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("gather: %v", err)
			}
			byName := map[string]*io_prometheus_client.MetricFamily{}
			for _, f := range families {
				byName[f.GetName()] = f
			}
			for _, metricName := range []string{
				"gateway_admission_decisions_total",
				"gateway_admission_budget_exhausted_total",
				"gateway_admission_shed_total",
				"gateway_admission_in_flight",
				"gateway_admission_limit",
			} {
				if _, ok := byName[metricName]; !ok {
					t.Fatalf("missing Prometheus metric %q", metricName)
				}
			}
			if got := byName["gateway_admission_budget_exhausted_total"].GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Fatalf("budget_exhausted counter: want 1, got %v", got)
			}
			if got := byName["gateway_admission_in_flight"].GetMetric()[0].GetGauge().GetValue(); got != 3 {
				t.Fatalf("in_flight gauge: want 3, got %v", got)
			}
			if got := byName["gateway_admission_limit"].GetMetric()[0].GetGauge().GetValue(); got != 3 {
				t.Fatalf("limit gauge: want 3, got %v", got)
			}

			for _, l := range leases {
				l.Success()
			}
			// Idempotent double release should not drive in_flight negative.
			leases[0].Success()
			if lim.InFlight() != 0 {
				t.Fatalf("expected in_flight=0 after releases, got %d", lim.InFlight())
			}
		})
	}
}

func TestMiddlewareHTTPAttributionAndUpstreamDrops(t *testing.T) {
	lim, err := NewGradientLimiter(Config{
		Layer:        LayerAIGateway,
		Endpoint:     "/v1/embeddings",
		InitialLimit: 2,
		MinLimit:     1,
		MaxLimit:     8,
		RetryAfter:   250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := lim.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			entered <- struct{}{}
			<-release
			w.WriteHeader(http.StatusOK)
		case "/bad":
			w.WriteHeader(http.StatusBadRequest)
		case "/overload":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/hold", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()
	}
	<-entered
	<-entered

	// 3rd concurrent request should be shed immediately with 429 + JSON attribution.
	req := httptest.NewRequest(http.MethodPost, "/ok", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
	if rec.Header().Get("X-Admission-Layer") != string(LayerAIGateway) {
		t.Fatalf("missing X-Admission-Layer header: %q", rec.Header().Get("X-Admission-Layer"))
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON body: %v", err)
	}
	if body["error"] != CodeBudgetExhausted || body["event"] != CodeAdmissionShed || body["layer"] != string(LayerAIGateway) {
		t.Fatalf("unexpected shed JSON body: %+v", body)
	}
	if int(body["in_flight"].(float64)) != 2 || int(body["limit"].(float64)) != 2 {
		t.Fatalf("unexpected in_flight/limit in body: %+v", body)
	}

	close(release)
	wg.Wait()

	// Exercise 400 (ignored) and 503 (dropped) classification.
	for _, path := range []string{"/bad", "/overload", "/ok"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}
	snap := lim.Snapshot()
	if snap.IgnoredTotal != 1 || snap.DroppedTotal != 1 || snap.SuccessTotal != 3 {
		t.Fatalf("unexpected outcome totals: ignored=%d dropped=%d success=%d",
			snap.IgnoredTotal, snap.DroppedTotal, snap.SuccessTotal)
	}
}

func TestConcurrentStressRaceSafety(t *testing.T) {
	lim, err := NewGradientLimiter(Config{
		Layer:            LayerTenantLedger,
		InitialLimit:     12,
		MinLimit:         2,
		MaxLimit:         32,
		WindowDuration:   2 * time.Millisecond,
		WindowMinSamples: 4,
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}

	reg := prometheus.NewRegistry()
	_ = reg.Register(lim.Collector())

	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 120; i++ {
				lease, err := lim.Acquire(context.Background())
				if err != nil {
					var rej *Rejection
					if !errors.As(err, &rej) || rej.Code != CodeBudgetExhausted {
						t.Errorf("unexpected error: %v", err)
						return
					}
					continue
				}
				if i%17 == 0 {
					lease.Dropped()
				} else if i%19 == 0 {
					lease.Ignore()
				} else {
					lease.Success()
				}
				if i%25 == 0 {
					_ = lim.Snapshot()
					_, _ = reg.Gather()
				}
			}
		}(g)
	}
	wg.Wait()

	snap := lim.Snapshot()
	if snap.InFlight != 0 {
		t.Fatalf("expected InFlight=0 after stress test, got %d", snap.InFlight)
	}
	if snap.AdmittedTotal+snap.BudgetExhaustedTotal != 24*120 {
		t.Fatalf("decision accounting mismatch: admitted=%d exhausted=%d",
			snap.AdmittedTotal, snap.BudgetExhaustedTotal)
	}
}

type simPhaseSpec struct {
	name          string
	requests      int
	interArrival  time.Duration
	upstreamSlots int
	serviceTime   time.Duration
	sla           time.Duration
}

type simPhaseResult struct {
	name          string
	attempted     int
	admitted      int
	shed          int
	good          int
	timedOut      int
	goodputPerSec float64
	p50           time.Duration
	p95           time.Duration
	p99           time.Duration
	steadyP99     time.Duration
	endLimit      int
	minLimitSeen  int
}

func percentileDuration(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// runDiscreteOverloadSim executes deterministic discrete-event phases over an
// upstream worker pool of `upstreamSlots` workers, advancing a shared virtual
// clock (`now`) so queuing dynamics and SLA timeouts are completely free of OS
// scheduler jitter.
func runDiscreteOverloadSim(
	now *time.Time,
	admit func() (release func(dropped bool), allowed bool),
	limitFn func() int,
	phases []simPhaseSpec,
) ([]simPhaseResult, error) {
	type inFlightReq struct {
		arriveAt   time.Time
		finishAt   time.Time
		sla        time.Duration
		release    func(bool)
		phaseIndex int
	}

	// Each phase keeps its own stats.
	results := make([]simPhaseResult, len(phases))
	rttsByPhase := make([][]time.Duration, len(phases))
	for i := range phases {
		results[i].name = phases[i].name
		results[i].minLimitSeen = limitFn()
	}

	var active []inFlightReq
	var workerFree []time.Time // free timestamps for current phase's slots

	drainUntil := func(until time.Time) {
		for {
			earliestIdx := -1
			var earliest time.Time
			for i, req := range active {
				if !req.finishAt.After(until) && (earliestIdx == -1 || req.finishAt.Before(earliest)) {
					earliestIdx = i
					earliest = req.finishAt
				}
			}
			if earliestIdx == -1 {
				break
			}
			req := active[earliestIdx]
			active[earliestIdx] = active[len(active)-1]
			active = active[:len(active)-1]

			*now = req.finishAt
			rtt := req.finishAt.Sub(req.arriveAt)
			timedOut := rtt > req.sla
			req.release(timedOut)

			p := req.phaseIndex
			rttsByPhase[p] = append(rttsByPhase[p], rtt)
			if timedOut {
				results[p].timedOut++
			} else {
				results[p].good++
			}
			if cur := limitFn(); cur < results[p].minLimitSeen {
				results[p].minLimitSeen = cur
			}
		}
	}

	for pIdx, ph := range phases {
		// Resize upstream slot array for this phase.
		newSlots := make([]time.Time, ph.upstreamSlots)
		for i := range newSlots {
			if i < len(workerFree) {
				newSlots[i] = workerFree[i]
			} else {
				newSlots[i] = *now
			}
		}
		workerFree = newSlots

		phaseStart := *now
		for r := 0; r < ph.requests; r++ {
			arr := phaseStart.Add(time.Duration(r) * ph.interArrival)
			drainUntil(arr)
			*now = arr

			results[pIdx].attempted++
			release, ok := admit()
			if !ok {
				results[pIdx].shed++
				continue
			}
			results[pIdx].admitted++

			// Pick earliest free upstream worker slot (FIFO M/D/c queue).
			slotIdx := 0
			for i := 1; i < len(workerFree); i++ {
				if workerFree[i].Before(workerFree[slotIdx]) {
					slotIdx = i
				}
			}
			startWork := arr
			if workerFree[slotIdx].After(startWork) {
				startWork = workerFree[slotIdx]
			}
			// Realistic thrashing penalty when admitted concurrency exceeds 2x slots.
			service := ph.serviceTime
			if excess := len(active) + 1 - 2*ph.upstreamSlots; excess > 0 {
				service += time.Duration(excess) * 250 * time.Microsecond
			}
			finish := startWork.Add(service)
			workerFree[slotIdx] = finish

			active = append(active, inFlightReq{
				arriveAt:   arr,
				finishAt:   finish,
				sla:        ph.sla,
				release:    release,
				phaseIndex: pIdx,
			})
		}

		// Drain remaining requests in this phase.
		var maxFinish time.Time
		for _, req := range active {
			if req.finishAt.After(maxFinish) {
				maxFinish = req.finishAt
			}
		}
		if maxFinish.After(*now) {
			drainUntil(maxFinish)
			*now = maxFinish
		}
		phaseDur := now.Sub(phaseStart)
		if phaseDur <= 0 {
			phaseDur = time.Millisecond
		}
		results[pIdx].goodputPerSec = float64(results[pIdx].good) / phaseDur.Seconds()
		results[pIdx].endLimit = limitFn()
		rawRTTs := rttsByPhase[pIdx]
		if len(rawRTTs) >= 4 {
			steady := slices.Clone(rawRTTs[len(rawRTTs)/2:])
			slices.Sort(steady)
			results[pIdx].steadyP99 = percentileDuration(steady, 0.99)
		}
		slices.Sort(rawRTTs)
		results[pIdx].p50 = percentileDuration(rawRTTs, 0.50)
		results[pIdx].p95 = percentileDuration(rawRTTs, 0.95)
		results[pIdx].p99 = percentileDuration(rawRTTs, 0.99)
	}
	return results, nil
}

func TestCompareGoodputAndP99_SpikeAndSlowDependency(t *testing.T) {
	const (
		staticLimit = 32
		sla         = 18 * time.Millisecond
	)

	phases := []simPhaseSpec{
		{
			name:          "normal",
			requests:      200,
			interArrival:  1200 * time.Microsecond, // ~833 req/s within 8-slot capacity (2000 req/s)
			upstreamSlots: 8,
			serviceTime:   4 * time.Millisecond,
			sla:           sla,
		},
		{
			name:          "overload_slow_dep",
			requests:      800,
			interArrival:  400 * time.Microsecond, // 2500 req/s spike while upstream drops to 4 slow slots
			upstreamSlots: 4,
			serviceTime:   6 * time.Millisecond, // max upstream capacity = 667 req/s
			sla:           sla,
		},
		{
			name:          "recovery",
			requests:      400,
			interArrival:  800 * time.Microsecond, // 1250 req/s well within recovered 8-slot capacity
			upstreamSlots: 8,
			serviceTime:   4 * time.Millisecond,
			sla:           sla,
		},
	}

	// 1. Static semaphore baseline (fixed limit = 32).
	stNow := time.Unix(1_700_000_000, 0)
	stInFlight := 0
	stAdmit := func() (func(bool), bool) {
		if stInFlight >= staticLimit {
			return nil, false
		}
		stInFlight++
		return func(bool) { stInFlight-- }, true
	}
	stRes, err := runDiscreteOverloadSim(&stNow, stAdmit, func() int { return staticLimit }, phases)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Adaptive GradientLimiter (initial limit = 32).
	grNow := time.Unix(1_700_000_000, 0)
	lim, err := NewGradientLimiter(Config{
		Layer:              LayerAIGateway,
		Endpoint:           "/v1/inference",
		InitialLimit:       staticLimit,
		MinLimit:           3,
		MaxLimit:           64,
		MinRTTWindow:       30 * time.Second,
		WindowDuration:     12 * time.Millisecond,
		WindowMinSamples:   6,
		Tolerance:          1.5,
		Smoothing:          0.35,
		RTTAlpha:           0.30,
		AppLimitedRatio:    0.35,
		CongestionBackoff:  0.80,
		MaxGrowthPerWindow: 2.0,
		Now:                func() time.Time { return grNow },
	})
	if err != nil {
		t.Fatalf("NewGradientLimiter: %v", err)
	}
	grAdmit := func() (func(bool), bool) {
		lease, err := lim.TryAcquire()
		if err != nil {
			return nil, false
		}
		return func(dropped bool) {
			if dropped {
				lease.Dropped()
			} else {
				lease.Success()
			}
		}, true
	}
	grRes, err := runDiscreteOverloadSim(&grNow, grAdmit, lim.Limit, phases)
	if err != nil {
		t.Fatal(err)
	}
	snap := lim.Snapshot()

	t.Logf("=== Spike + Slow Dependency Comparison (SLA=%s) ===", sla)
	for i := range phases {
		st, gr := stRes[i], grRes[i]
		t.Logf("StaticSemaphore(32)  %-17s: goodput=%6.1f/s p50=%7s p95=%7s p99=%7s steadyP99=%7s (good=%d timeout=%d shed=%d limit=%d)",
			st.name, st.goodputPerSec, st.p50, st.p95, st.p99, st.steadyP99, st.good, st.timedOut, st.shed, st.endLimit)
		t.Logf("GradientLimiter(32)  %-17s: goodput=%6.1f/s p50=%7s p95=%7s p99=%7s steadyP99=%7s (good=%d timeout=%d shed=%d minLim=%d endLim=%d)",
			gr.name, gr.goodputPerSec, gr.p50, gr.p95, gr.p99, gr.steadyP99, gr.good, gr.timedOut, gr.shed, gr.minLimitSeen, gr.endLimit)
	}
	t.Logf("Gradient Attribution Metrics         : layer=%s admitted=%d budget_exhausted=%d admission_shed=%d minRTT=%s shortRTT=%s gradient=%.3f",
		snap.Layer, snap.AdmittedTotal, snap.BudgetExhaustedTotal, snap.AdmissionShedTotal, snap.MinRTT, snap.ShortRTT, snap.Gradient)

	stOver, grOver := stRes[1], grRes[1]
	grRec := grRes[2]

	if grOver.p99 >= stOver.p99 {
		t.Fatalf("expected GradientLimiter p99 (%s) < StaticSemaphore p99 (%s) during overload",
			grOver.p99, stOver.p99)
	}
	if grOver.goodputPerSec <= stOver.goodputPerSec {
		t.Fatalf("expected GradientLimiter goodput (%.1f/s) > StaticSemaphore goodput (%.1f/s) during overload",
			grOver.goodputPerSec, stOver.goodputPerSec)
	}
	if grOver.endLimit >= staticLimit {
		t.Fatalf("expected GradientLimiter to shrink below initial %d under overload, got %d",
			staticLimit, grOver.endLimit)
	}
	if grRec.endLimit <= grOver.minLimitSeen {
		t.Fatalf("expected GradientLimiter to recover above minLimit=%d after overload cleared, got %d",
			grOver.minLimitSeen, grRec.endLimit)
	}
	if snap.BudgetExhaustedTotal == 0 || snap.BudgetExhaustedTotal != snap.AdmissionShedTotal {
		t.Fatalf("expected explicit budget_exhausted == admission_shed > 0, got exhausted=%d shed=%d",
			snap.BudgetExhaustedTotal, snap.AdmissionShedTotal)
	}
}

func BenchmarkGradientTryAcquireRelease(b *testing.B) {
	lim, err := NewGradientLimiter(Config{
		Layer:        LayerAIGateway,
		InitialLimit: 64,
		MinLimit:     8,
		MaxLimit:     256,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lease, err := lim.TryAcquire()
			if err == nil {
				lease.Success()
			}
		}
	})
}
