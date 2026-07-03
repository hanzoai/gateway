//go:build legacy
// +build legacy

// Package gateway — base_ha backend upstream.
//
// Implements the `base_ha` upstream kind for Hanzo Base HA clusters
// (hanzoai/base-ha). One writer, N replicas. The gateway is the leader
// tracker — clients never see a 307.
//
// Per-backend `extra_config`:
//
//	"github.com/hanzoai/gateway/base_ha": {
//	  "service_dns":           "foo-hs.hanzo.svc.cluster.local",
//	  "port":                  8090,
//	  "leader_poll_interval":  "1s",
//	  "write_methods":         ["POST","PUT","PATCH","DELETE"],
//	  "read_your_writes_ttl":  "5s"
//	}
//
// The enclosing backend's single Host is the ClusterIP service (round-robin
// for reads). The base_ha factory overrides the transport:
//
//   - write methods (or X-Base-Writer: required header) → writer pod
//   - reads → round-robin via the ClusterIP service
//   - for 5s after a write, same client (X-Forwarded-For + X-Org-Id) pins to
//     the writer for read-your-writes consistency
//
// Leader discovery: a single goroutine per service_dns polls
// GET http://{service_dns}:{port}/_ha/leader every leader_poll_interval.
// The response is stored in an atomic.Pointer so the hot path is lock-free.
// On writer 5xx/connect-refused, the poller is force-refreshed and one retry
// is issued. Two consecutive 5xx = hard fail (no retry storm on OOM).
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	metric "github.com/luxfi/metric"
)

// BaseHANamespace is the extra_config key for base_ha upstreams.
const BaseHANamespace = "github.com/hanzoai/gateway/base_ha"

// BaseHAConfig mirrors the JSON schema documented above. Zero-value defaults
// are applied at factory time.
type BaseHAConfig struct {
	// ServiceDNS is the headless or ClusterIP DNS name of the base-ha
	// service. Used only for the /_ha/leader poll — the actual read path
	// uses the enclosing backend Host (round-robin).
	ServiceDNS string `json:"service_dns"`
	// Port is the HTTP port the base-ha pods listen on.
	Port int `json:"port"`
	// LeaderPollInterval is parsed by time.ParseDuration. Default 1s.
	LeaderPollInterval string `json:"leader_poll_interval"`
	// WriteMethods lists HTTP methods that require writer pinning.
	// Default: POST, PUT, PATCH, DELETE.
	WriteMethods []string `json:"write_methods"`
	// ReadYourWritesTTL is how long after a write the same client pins
	// to the writer for reads. Default 5s. Set to "0s" to disable.
	ReadYourWritesTTL string `json:"read_your_writes_ttl"`
}

// writerState is a read-mostly snapshot written by the leader poll goroutine
// and read by every request. Loads are atomic so the hot path is lock-free.
type writerState struct {
	leaderURL    string
	nodeID       string
	term         uint64
	leaseExpires time.Time
	fetchedAt    time.Time
}

// baseHAUpstream is one leader-tracker goroutine + its atomic snapshot.
// One instance per distinct service_dns (pool-keyed).
type baseHAUpstream struct {
	cfg        BaseHAConfig
	pollURL    string // http://{service_dns}:{port}/_ha/leader
	interval   time.Duration
	ryWTTL     time.Duration
	writeSet   map[string]struct{}
	httpClient *http.Client

	state atomic.Pointer[writerState]

	// forceRefresh is signaled by request handlers when they see a writer
	// failure. The poll loop drains any outstanding signal and issues an
	// out-of-schedule leader fetch.
	forceRefresh chan struct{}

	// rywPins records per-client (X-Forwarded-For + X-Org-Id) write times
	// so subsequent reads within ryWTTL land on the same writer. Small map,
	// swept on write.
	rywMu   sync.Mutex
	rywPins map[string]time.Time

	log     logging.Logger
	stopOnc sync.Once
	stopCh  chan struct{}
}

// baseHAPool is keyed on service_dns so multiple endpoints pointing at the
// same base-ha cluster share exactly one poll goroutine.
var baseHAPool = struct {
	sync.Mutex
	upstreams map[string]*baseHAUpstream
}{upstreams: make(map[string]*baseHAUpstream)}

func getBaseHAUpstream(cfg BaseHAConfig, logger logging.Logger) (*baseHAUpstream, error) {
	baseHAPool.Lock()
	defer baseHAPool.Unlock()
	key := fmt.Sprintf("%s:%d", cfg.ServiceDNS, cfg.Port)
	if up, ok := baseHAPool.upstreams[key]; ok {
		return up, nil
	}
	up, err := newBaseHAUpstream(cfg, logger)
	if err != nil {
		return nil, err
	}
	baseHAPool.upstreams[key] = up
	return up, nil
}

func newBaseHAUpstream(cfg BaseHAConfig, logger logging.Logger) (*baseHAUpstream, error) {
	if cfg.ServiceDNS == "" {
		return nil, errors.New("base_ha: service_dns is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("base_ha: invalid port %d", cfg.Port)
	}
	interval := time.Second
	if cfg.LeaderPollInterval != "" {
		d, err := time.ParseDuration(cfg.LeaderPollInterval)
		if err != nil {
			return nil, fmt.Errorf("base_ha: parse leader_poll_interval: %w", err)
		}
		if d < 100*time.Millisecond {
			return nil, fmt.Errorf("base_ha: leader_poll_interval %s below 100ms floor", d)
		}
		interval = d
	}
	ryw := 5 * time.Second
	if cfg.ReadYourWritesTTL != "" {
		d, err := time.ParseDuration(cfg.ReadYourWritesTTL)
		if err != nil {
			return nil, fmt.Errorf("base_ha: parse read_your_writes_ttl: %w", err)
		}
		if d < 0 {
			return nil, fmt.Errorf("base_ha: negative read_your_writes_ttl %s", d)
		}
		ryw = d
	}
	writeSet := defaultWriteSet()
	if len(cfg.WriteMethods) > 0 {
		writeSet = make(map[string]struct{}, len(cfg.WriteMethods))
		for _, m := range cfg.WriteMethods {
			writeSet[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
		}
	}
	up := &baseHAUpstream{
		cfg:          cfg,
		pollURL:      fmt.Sprintf("http://%s:%d/_ha/leader", cfg.ServiceDNS, cfg.Port),
		interval:     interval,
		ryWTTL:       ryw,
		writeSet:     writeSet,
		httpClient:   &http.Client{Timeout: interval},
		forceRefresh: make(chan struct{}, 1),
		rywPins:      make(map[string]time.Time, 256),
		log:          logger,
		stopCh:       make(chan struct{}),
	}
	// Seed the snapshot synchronously so the first request after factory
	// init doesn't race a cold cache. Missing leader is non-fatal — poll
	// loop will retry.
	_ = up.refresh()
	go up.pollLoop()
	return up, nil
}

func defaultWriteSet() map[string]struct{} {
	return map[string]struct{}{
		http.MethodPost:   {},
		http.MethodPut:    {},
		http.MethodPatch:  {},
		http.MethodDelete: {},
	}
}

// pollLoop refreshes the writer state on every tick. It also drains the
// forceRefresh channel so request handlers can nudge the poller after a
// writer failure without spawning a new goroutine.
func (u *baseHAUpstream) pollLoop() {
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		select {
		case <-u.stopCh:
			return
		case <-t.C:
			_ = u.refresh()
		case <-u.forceRefresh:
			_ = u.refresh()
			// Drain any second signal racing behind us so we don't
			// storm the backend.
			select {
			case <-u.forceRefresh:
			default:
			}
		}
	}
}

// refresh issues one GET /_ha/leader and stores the result. Accepts a
// narrow schema contract — see base-ha/ha_endpoints.go LeaderResponse.
func (u *baseHAUpstream) refresh() error {
	metricLeaderPolls.Inc()
	ctx, cancel := context.WithTimeout(context.Background(), u.interval)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.pollURL, nil)
	if err != nil {
		return err
	}
	resp, err := u.httpClient.Do(req)
	if err != nil {
		metricLeaderPollErrors.Inc()
		u.log.Debug(fmt.Sprintf("[BACKEND: base_ha] poll %s: %v", u.pollURL, err))
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		metricLeaderPollErrors.Inc()
		return fmt.Errorf("poll %s: status %d", u.pollURL, resp.StatusCode)
	}
	var body struct {
		LeaderURL    string    `json:"leader_url"`
		NodeID       string    `json:"node_id"`
		Term         uint64    `json:"term"`
		LeaseExpires time.Time `json:"lease_expires"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&body); err != nil {
		metricLeaderPollErrors.Inc()
		return fmt.Errorf("poll %s: decode: %w", u.pollURL, err)
	}
	if body.LeaderURL == "" {
		// Base never elected or electing now — keep the last-known state.
		return errors.New("empty leader_url")
	}
	prev := u.state.Load()
	u.state.Store(&writerState{
		leaderURL:    body.LeaderURL,
		nodeID:       body.NodeID,
		term:         body.Term,
		leaseExpires: body.LeaseExpires,
		fetchedAt:    time.Now(),
	})
	if prev == nil || prev.term != body.Term {
		metricLeaderChanges.Inc()
		u.log.Info(fmt.Sprintf("[BACKEND: base_ha] writer elected: %s (node=%s, term=%d)",
			body.LeaderURL, body.NodeID, body.Term))
	}
	return nil
}

// close ends the poll goroutine. Called by tests only — the pool holds
// upstreams forever in production since the gateway lifetime is the process
// lifetime.
func (u *baseHAUpstream) close() {
	u.stopOnc.Do(func() { close(u.stopCh) })
}

// kickRefresh nudges the poll loop out of schedule. Non-blocking.
func (u *baseHAUpstream) kickRefresh() {
	select {
	case u.forceRefresh <- struct{}{}:
	default:
	}
}

// isWriteMethod consults the configured write set. Also fires on the
// opt-in header X-Base-Writer: required so callers can force writer
// targeting on a GET (e.g. sensitive reads).
func (u *baseHAUpstream) isWriteMethod(method string, headers map[string][]string) bool {
	if _, ok := u.writeSet[strings.ToUpper(method)]; ok {
		return true
	}
	return strings.EqualFold(firstHeader(headers, "X-Base-Writer"), "required")
}

// currentWriter returns the pinned writer URL or "" when no writer is known
// yet (transient — only at cold start or after sustained outage).
func (u *baseHAUpstream) currentWriter() string {
	s := u.state.Load()
	if s == nil {
		return ""
	}
	// Fail-secure: if the lease has expired AND we haven't refreshed in
	// >2x the poll interval, the view is stale. Return "" so the caller
	// gets an honest 503 instead of a doomed retry against a dead pod.
	now := time.Now()
	leaseDead := !s.leaseExpires.IsZero() && now.After(s.leaseExpires)
	pollStale := now.Sub(s.fetchedAt) > 2*u.interval
	if leaseDead && pollStale {
		return ""
	}
	return s.leaderURL
}

// rywPinActive returns true if this client wrote recently enough to warrant
// pinning their next read to the writer. Sweeps expired entries on each
// call to keep the map small.
func (u *baseHAUpstream) rywPinActive(clientKey string) bool {
	if u.ryWTTL == 0 || clientKey == "" {
		return false
	}
	now := time.Now()
	u.rywMu.Lock()
	defer u.rywMu.Unlock()
	// Opportunistic sweep — O(n) but the map is bounded by concurrent
	// writers which is small.
	for k, t := range u.rywPins {
		if now.Sub(t) > u.ryWTTL {
			delete(u.rywPins, k)
		}
	}
	t, ok := u.rywPins[clientKey]
	return ok && now.Sub(t) <= u.ryWTTL
}

// markWrite records a write by clientKey so next reads within ryWTTL stick.
func (u *baseHAUpstream) markWrite(clientKey string) {
	if u.ryWTTL == 0 || clientKey == "" {
		return
	}
	u.rywMu.Lock()
	u.rywPins[clientKey] = time.Now()
	u.rywMu.Unlock()
}

// BaseHABackendFactory wraps the next BackendFactory with base_ha routing.
// Backends without BaseHANamespace in their extra_config fall through.
func BaseHABackendFactory(logger logging.Logger, next proxy.BackendFactory) proxy.BackendFactory {
	return func(remote *config.Backend) proxy.Proxy {
		raw, ok := remote.ExtraConfig[BaseHANamespace]
		if !ok {
			return next(remote)
		}
		b, err := json.Marshal(raw)
		if err != nil {
			logger.Error("[BACKEND: base_ha] marshal config:", err.Error())
			return next(remote)
		}
		var cfg BaseHAConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			logger.Error("[BACKEND: base_ha] parse config:", err.Error())
			return next(remote)
		}
		up, err := getBaseHAUpstream(cfg, logger)
		if err != nil {
			logger.Error("[BACKEND: base_ha] init:", err.Error())
			return next(remote)
		}
		logger.Info(fmt.Sprintf("[BACKEND: base_ha] %s → leader-tracked via %s (poll=%s, ryw=%s)",
			remote.URLPattern, up.pollURL, up.interval, up.ryWTTL))
		return newBaseHAProxy(remote, up)
	}
}

// newBaseHAProxy builds the per-backend proxy function. Reads use the
// enclosing backend Host (round-robin via ClusterIP DNS); writes use the
// atomic writer snapshot.
func newBaseHAProxy(remote *config.Backend, up *baseHAUpstream) proxy.Proxy {
	readHost := ""
	if len(remote.Host) > 0 {
		readHost = remote.Host[0]
	}
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		// Never follow 307s automatically — the writer pin handles
		// redirection. A 307 here means the backend disagrees with us
		// about the current leader; we surface that as a server error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return func(ctx context.Context, req *proxy.Request) (*proxy.Response, error) {
		isWrite := up.isWriteMethod(req.Method, req.Headers)
		clientKey := clientPinKey(req.Headers)
		pinToWriter := isWrite || up.rywPinActive(clientKey)

		var target string
		if pinToWriter {
			target = up.currentWriter()
			if target == "" {
				metricNoWriter.Inc()
				return errorResponse(http.StatusServiceUnavailable, `{"error":"no_writer"}`), nil
			}
		} else {
			if readHost == "" {
				return errorResponse(http.StatusBadGateway, `{"error":"base_ha_no_host"}`), nil
			}
			target = readHost
		}

		// Body must be buffered so we can replay it on writer-refresh retry.
		var bodyBytes []byte
		if req.Body != nil {
			bb, err := io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("base_ha: read body: %w", err)
			}
			bodyBytes = bb
		}

		resp, err := dispatchBaseHA(ctx, httpClient, target, req, bodyBytes)
		// Writer failure path: one force-refresh + one retry (potentially
		// against a new writer after failover, or the same writer if
		// failover hasn't happened yet). No second retry — OOM / sustained
		// 5xx must NOT cascade into a retry storm.
		if pinToWriter && isWriterFailure(resp, err) {
			metricWriterFailures.Inc()
			if resp != nil {
				_ = resp.Body.Close()
			}
			// Force a leader refresh and give it up to 1.5x the poll
			// interval to land. Under healthy failover this lets us hop
			// to the new writer in ~1.5s.
			up.kickRefresh()
			deadline := time.Now().Add(up.interval + up.interval/2)
			for time.Now().Before(deadline) {
				if w := up.currentWriter(); w != "" && w != target {
					target = w
					break
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(25 * time.Millisecond):
				}
			}
			// Whether target changed or not, issue exactly one retry.
			// If the writer has self-healed, same target succeeds. If
			// the leader flipped, we're on the new writer. Either way,
			// we do NOT retry a third time on failure.
			retryTarget := up.currentWriter()
			if retryTarget == "" {
				// Refresh confirmed no writer (stale-cache guard).
				// Fail secure without a second network attempt.
				metricWriterFailuresFatal.Inc()
				return errorResponse(http.StatusServiceUnavailable, `{"error":"writer_unreachable"}`), nil
			}
			resp, err = dispatchBaseHA(ctx, httpClient, retryTarget, req, bodyBytes)
			if err != nil || (resp != nil && resp.StatusCode >= 500) {
				metricWriterFailuresFatal.Inc()
				if err != nil {
					return nil, fmt.Errorf("base_ha: writer retry failed: %w", err)
				}
				// Stream the 5xx body back to the caller — it's the
				// authoritative answer from the (possibly new) writer.
				return responseFromHTTP(ctx, resp), nil
			}
		}
		if err != nil {
			return nil, err
		}

		// On successful write, pin this client for ryWTTL so their next
		// read lands on the writer (read-your-writes).
		if isWrite && resp.StatusCode < http.StatusInternalServerError {
			up.markWrite(clientKey)
		}

		// Stamp X-Base-TxSeq from the upstream response header. This is
		// a cheap hint the FE can use to gate UI optimistic-lock displays.
		if seq := resp.Header.Get("X-Base-TxSeq"); seq != "" {
			// Already on the response header — passthrough.
			_ = seq
		}
		return responseFromHTTP(ctx, resp), nil
	}
}

// dispatchBaseHA issues one upstream request. target is either a fully
// qualified writer URL (http://foo-1.foo-hs:8090) or a DNS name (foo.hanzo.svc).
func dispatchBaseHA(ctx context.Context, c *http.Client, target string, req *proxy.Request, body []byte) (*http.Response, error) {
	// If target lacks a scheme, assume HTTP. Kubernetes ClusterIP DNS
	// without scheme is the common read case.
	full := target
	if !strings.Contains(full, "://") {
		full = "http://" + full
	}
	full = strings.TrimRight(full, "/") + req.Path
	if len(req.Query) > 0 {
		full += "?" + req.Query.Encode()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	hreq, err := http.NewRequestWithContext(ctx, req.Method, full, reader)
	if err != nil {
		return nil, fmt.Errorf("base_ha: build request: %w", err)
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	return c.Do(hreq)
}

// isWriterFailure classifies a writer-targeted response/err as retryable.
// 5xx and connect-refused both trigger one refresh+retry. 4xx does not —
// those are application errors (validation, auth) not writer faults.
func isWriterFailure(resp *http.Response, err error) bool {
	if err != nil {
		// Connect-refused, DNS lookup fail, TLS mismatch, EOF.
		var netErr net.Error
		if errors.As(err, &netErr) {
			return true
		}
		// errors.Is(err, syscall.ECONNREFUSED) catches the most common case.
		return true
	}
	if resp == nil {
		return true
	}
	return resp.StatusCode >= 500
}

// clientPinKey identifies a client for read-your-writes. X-Forwarded-For
// (first IP) + X-Org-Id is usually good enough — same client-IP and same
// tenant sees read-your-writes. Falls back to X-User-Id when no IP header
// is available (e.g. in-cluster calls behind ingress).
func clientPinKey(headers map[string][]string) string {
	ip := firstHeader(headers, "X-Forwarded-For")
	if i := strings.IndexByte(ip, ','); i > 0 {
		ip = strings.TrimSpace(ip[:i])
	}
	org := firstHeader(headers, "X-Org-Id")
	user := firstHeader(headers, "X-User-Id")
	if ip == "" && user == "" {
		return ""
	}
	return ip + "|" + org + "|" + user
}

// Prometheus metrics — guarded by once so tests can import without dupes.
var (
	metricLeaderPolls = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_leader_polls_total",
		Help: "Total GET /_ha/leader polls issued.",
	})
	metricLeaderPollErrors = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_leader_poll_errors_total",
		Help: "Leader poll failures (timeout, connection refused, non-200, decode error).",
	})
	metricLeaderChanges = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_leader_changes_total",
		Help: "Observed writer changes (term increased).",
	})
	metricWriterFailures = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_writer_failures_total",
		Help: "Writer-targeted requests that returned 5xx or failed to connect and triggered a refresh+retry.",
	})
	metricWriterFailuresFatal = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_writer_failures_fatal_total",
		Help: "Writer-targeted requests that failed on the retry path.",
	})
	metricNoWriter = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_ha_no_writer_total",
		Help: "Write requests rejected because no writer is known yet.",
	})
)

// Metrics above are registered on luxfi/metric's DefaultRegistry at
// construction (NewCounter create-and-registers), so no explicit
// registration pass is needed — unlike prometheus/client_golang's
// two-step create-then-Register.
