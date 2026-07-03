//go:build legacy
// +build legacy

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
)

// leaderStub serves /_ha/leader and optionally flips the returned writer URL.
type leaderStub struct {
	mu        sync.Mutex
	leaderURL string
	nodeID    string
	term      uint64
	leaseExp  time.Time
}

func (l *leaderStub) set(url, nodeID string, term uint64, leaseExp time.Time) {
	l.mu.Lock()
	l.leaderURL = url
	l.nodeID = nodeID
	l.term = term
	l.leaseExp = leaseExp
	l.mu.Unlock()
}

func (l *leaderStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.leaderURL == "" {
			http.Error(w, "no leader", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"leader_url":    l.leaderURL,
			"node_id":       l.nodeID,
			"term":          l.term,
			"lease_expires": l.leaseExp,
		})
	})
}

// endpointStub is a fake base-ha pod; records the method+path it received
// and returns a configurable status.
type endpointStub struct {
	name   string
	mu     sync.Mutex
	calls  []string
	status int32 // atomic
}

func (e *endpointStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.calls = append(e.calls, r.Method+" "+r.URL.Path)
		e.mu.Unlock()
		st := int(atomic.LoadInt32(&e.status))
		if st == 0 {
			st = http.StatusOK
		}
		w.Header().Set("X-Base-TxSeq", "42")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"pod":%q}`, e.name)))
	})
}

func (e *endpointStub) setStatus(code int) { atomic.StoreInt32(&e.status, int32(code)) }

func (e *endpointStub) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.calls))
	copy(out, e.calls)
	return out
}

// --- helper --------------------------------------------------------------

func buildTestProxy(t *testing.T, dns string, port int, extra ...func(*BaseHAConfig)) (proxy.Proxy, *baseHAUpstream) {
	t.Helper()
	cfg := BaseHAConfig{
		ServiceDNS:         dns,
		Port:               port,
		LeaderPollInterval: "100ms",
		ReadYourWritesTTL:  "200ms",
	}
	for _, f := range extra {
		f(&cfg)
	}
	up, err := newBaseHAUpstream(cfg, logging.NoOp)
	if err != nil {
		t.Fatalf("newBaseHAUpstream: %v", err)
	}
	t.Cleanup(up.close)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{fmt.Sprintf("http://%s:%d", dns, port)},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          cfg.ServiceDNS,
				"port":                 cfg.Port,
				"leader_poll_interval": cfg.LeaderPollInterval,
				"read_your_writes_ttl": cfg.ReadYourWritesTTL,
			},
		},
	}
	return newBaseHAProxy(remote, up), up
}

// pollUntilWriter blocks until the upstream observes a non-empty writer or
// the deadline expires. Used because refresh() is async from server start.
func pollUntilWriter(t *testing.T, up *baseHAUpstream, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if w := up.currentWriter(); w != "" {
			return w
		}
		up.kickRefresh()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("writer never discovered within %s", d)
	return ""
}

func newHAProxyRequest(method, path string, headers http.Header, body string) *proxy.Request {
	var rc io.ReadCloser
	if body != "" {
		rc = io.NopCloser(strings.NewReader(body))
	}
	return &proxy.Request{
		Method:  method,
		Path:    path,
		Query:   url.Values{},
		Headers: headers,
		Body:    rc,
	}
}

// --- tests ---------------------------------------------------------------

func TestBaseHAConfigRequiredFields(t *testing.T) {
	_, err := newBaseHAUpstream(BaseHAConfig{Port: 8090}, logging.NoOp)
	if err == nil {
		t.Fatalf("empty service_dns must error")
	}
	_, err = newBaseHAUpstream(BaseHAConfig{ServiceDNS: "x", Port: 0}, logging.NoOp)
	if err == nil {
		t.Fatalf("zero port must error")
	}
	_, err = newBaseHAUpstream(BaseHAConfig{ServiceDNS: "x", Port: 70000}, logging.NoOp)
	if err == nil {
		t.Fatalf("port > 65535 must error")
	}
	_, err = newBaseHAUpstream(BaseHAConfig{ServiceDNS: "x", Port: 8090, LeaderPollInterval: "10ms"}, logging.NoOp)
	if err == nil {
		t.Fatalf("poll interval < 100ms must error (retry-storm guard)")
	}
}

// TestBaseHAWritePinsToLeader proves POST lands on the writer URL returned
// by /_ha/leader, regardless of the enclosing backend Host.
func TestBaseHAWritePinsToLeader(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	reader := &endpointStub{name: "foo-1"}
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()
	readerSrv := httptest.NewServer(reader.handler())
	defer readerSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	// The read-host is deliberately the READER pod so we can tell where
	// the proxy actually sent the request.
	ru, _ := url.Parse(readerSrv.URL)
	_, _ = host, port

	p, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	// Point the enclosing Host at the reader so reads go there.
	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{"http://" + ru.Host},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          host,
				"port":                 port,
				"leader_poll_interval": "100ms",
			},
		},
	}
	p = newBaseHAProxy(remote, up)

	// Write → writer.
	resp, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", http.Header{}, `{"k":1}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.Metadata.StatusCode != http.StatusOK {
		t.Fatalf("write status: %d", resp.Metadata.StatusCode)
	}
	if calls := writer.snapshot(); len(calls) != 1 || calls[0] != "POST /x" {
		t.Fatalf("writer calls: %+v", calls)
	}
	if calls := reader.snapshot(); len(calls) != 0 {
		t.Fatalf("reader must not have seen the write: %+v", calls)
	}
}

// TestBaseHAReadHitsEnclosingHost proves GET goes to the Host (round-robin
// ClusterIP target), NOT the writer URL.
func TestBaseHAReadHitsEnclosingHost(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	svc := &endpointStub{name: "clusterip"}
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()
	svcSrv := httptest.NewServer(svc.handler())
	defer svcSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{svcSrv.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          host,
				"port":                 port,
				"leader_poll_interval": "100ms",
			},
		},
	}
	p := newBaseHAProxy(remote, up)
	_, err := p(context.Background(), newHAProxyRequest(http.MethodGet, "/r", http.Header{}, ""))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if calls := svc.snapshot(); len(calls) != 1 {
		t.Fatalf("read must hit ClusterIP host, got %+v", calls)
	}
	if calls := writer.snapshot(); len(calls) != 0 {
		t.Fatalf("read must not hit writer, got %+v", calls)
	}
}

// TestBaseHAReadYourWritesPinsReader proves that after a POST, the next
// GET from the same client (same X-Forwarded-For + X-Org-Id) goes to the
// writer (not the round-robin Host), within the configured TTL.
func TestBaseHAReadYourWritesPinsReader(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	svc := &endpointStub{name: "clusterip"}
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()
	svcSrv := httptest.NewServer(svc.handler())
	defer svcSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{svcSrv.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          host,
				"port":                 port,
				"leader_poll_interval": "100ms",
				"read_your_writes_ttl": "500ms",
			},
		},
	}
	p := newBaseHAProxy(remote, up)
	hdr := http.Header{
		"X-Forwarded-For": []string{"1.2.3.4"},
		"X-Org-Id":        []string{"org-a"},
	}

	// Write — marks the client for RYW.
	if _, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", hdr, `{}`)); err != nil {
		t.Fatal(err)
	}

	// Read within TTL — must pin to writer.
	if _, err := p(context.Background(), newHAProxyRequest(http.MethodGet, "/x", hdr, "")); err != nil {
		t.Fatal(err)
	}
	if got := writer.snapshot(); len(got) != 2 {
		t.Fatalf("writer should have seen write+read, got %+v", got)
	}
	if got := svc.snapshot(); len(got) != 0 {
		t.Fatalf("ClusterIP host must not have seen the pinned read, got %+v", got)
	}

	// After TTL, pin expires — read falls back to round-robin.
	time.Sleep(600 * time.Millisecond)
	if _, err := p(context.Background(), newHAProxyRequest(http.MethodGet, "/x", hdr, "")); err != nil {
		t.Fatal(err)
	}
	if got := svc.snapshot(); len(got) != 1 {
		t.Fatalf("post-TTL read should hit ClusterIP host once, got %+v", got)
	}
}

// TestBaseHAWriterHeaderForcesPin covers the X-Base-Writer: required
// opt-in: a GET with this header MUST go to the writer.
func TestBaseHAWriterHeaderForcesPin(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	svc := &endpointStub{name: "clusterip"}
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()
	svcSrv := httptest.NewServer(svc.handler())
	defer svcSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{svcSrv.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns": host,
				"port":        port,
			},
		},
	}
	p := newBaseHAProxy(remote, up)

	hdr := http.Header{"X-Base-Writer": []string{"required"}}
	if _, err := p(context.Background(), newHAProxyRequest(http.MethodGet, "/r", hdr, "")); err != nil {
		t.Fatal(err)
	}
	if got := writer.snapshot(); len(got) != 1 {
		t.Fatalf("X-Base-Writer: required must pin read to writer, got %+v", got)
	}
	if got := svc.snapshot(); len(got) != 0 {
		t.Fatalf("ClusterIP host must not see header-pinned read, got %+v", got)
	}
}

// TestBaseHAWriterFailureRefreshesLeaderAndRetries covers the 5xx/refused
// recovery path: writer returns 503 → refresh → next writer serves.
func TestBaseHAWriterFailureRefreshesLeaderAndRetries(t *testing.T) {
	writerA := &endpointStub{name: "foo-0"}
	writerA.setStatus(503)
	writerB := &endpointStub{name: "foo-1"}
	writerASrv := httptest.NewServer(writerA.handler())
	defer writerASrv.Close()
	writerBSrv := httptest.NewServer(writerB.handler())
	defer writerBSrv.Close()

	leader := &leaderStub{}
	leader.set(writerASrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{writerBSrv.URL}, // irrelevant for the write path
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          host,
				"port":                 port,
				"leader_poll_interval": "100ms",
			},
		},
	}
	p := newBaseHAProxy(remote, up)

	// Simulate the failover: leader stub now reports writerB as leader,
	// term bumped. The proxy doesn't know yet — the refresh must discover.
	flipDone := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		leader.set(writerBSrv.URL, "foo-1", 2, time.Now().Add(10*time.Second))
		close(flipDone)
	}()

	resp, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", http.Header{}, "{}"))
	<-flipDone
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.Metadata.StatusCode != http.StatusOK {
		t.Fatalf("final status: %d", resp.Metadata.StatusCode)
	}
	if got := writerA.snapshot(); len(got) != 1 {
		t.Fatalf("writerA (stale) should have been tried once: %+v", got)
	}
	if got := writerB.snapshot(); len(got) != 1 {
		t.Fatalf("writerB (new) should have served the retry: %+v", got)
	}
}

// TestBaseHAWriterDoubleFailureDoesNotStorm proves one-retry cap — if the
// refreshed writer is also failing, we return 503 rather than looping.
func TestBaseHAWriterDoubleFailureDoesNotStorm(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	writer.setStatus(503)
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{writerSrv.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns":          host,
				"port":                 port,
				"leader_poll_interval": "100ms",
			},
		},
	}
	p := newBaseHAProxy(remote, up)

	resp, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", http.Header{}, "{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.Metadata.StatusCode < 500 {
		t.Fatalf("expected 5xx after double failure, got %d", resp.Metadata.StatusCode)
	}
	// Exactly two calls: first + retry. NOT more.
	if got := len(writer.snapshot()); got != 2 {
		t.Fatalf("writer should have seen at most 2 attempts, got %d", got)
	}
}

// TestBaseHAStaleCacheFailsSecure proves that when the lease has expired
// AND we haven't heard from the poller in >2x the interval, a write is
// rejected with 503 instead of being sent to a known-dead pod.
func TestBaseHAStaleCacheFailsSecure(t *testing.T) {
	writerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer writerSrv.Close()

	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(-1*time.Hour))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	// Seed the snapshot then stop the poller so fetchedAt goes stale.
	_ = pollUntilWriter(t, up, 2*time.Second)
	up.close()
	// Force fetchedAt into the past to simulate sustained poll failure.
	prev := up.state.Load()
	up.state.Store(&writerState{
		leaderURL:    prev.leaderURL,
		nodeID:       prev.nodeID,
		term:         prev.term,
		leaseExpires: time.Now().Add(-1 * time.Minute), // expired
		fetchedAt:    time.Now().Add(-5 * time.Second), // > 2x interval
	})

	if up.currentWriter() != "" {
		t.Fatalf("stale state must return empty writer")
	}

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{writerSrv.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns": host,
				"port":        port,
			},
		},
	}
	p := newBaseHAProxy(remote, up)
	resp, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", http.Header{}, "{}"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Metadata.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503 on stale-cache write, got %d", resp.Metadata.StatusCode)
	}
}

// TestBaseHAForwardsHeaders proves gateway-injected identity headers
// (X-User-Id / X-Org-Id / X-Roles) propagate to the upstream pod.
func TestBaseHAForwardsHeaders(t *testing.T) {
	writer := &endpointStub{name: "foo-0"}
	writerSrv := httptest.NewServer(writer.handler())
	defer writerSrv.Close()
	leader := &leaderStub{}
	leader.set(writerSrv.URL, "foo-0", 1, time.Now().Add(10*time.Second))
	leaderSrv := httptest.NewServer(leader.handler())
	defer leaderSrv.Close()

	u, _ := url.Parse(leaderSrv.URL)
	host, port := splitHostPort(u.Host)
	_, up := buildTestProxy(t, host, port)
	_ = pollUntilWriter(t, up, 2*time.Second)

	// Instrument to capture headers at the writer side.
	var captured http.Header
	writer.mu.Lock()
	writer.calls = nil
	writer.mu.Unlock()
	// Replace writerSrv handler inline — we need to see headers.
	writerSrv.Close()
	realWriter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer realWriter.Close()
	leader.set(realWriter.URL, "foo-0", 2, time.Now().Add(10*time.Second))
	up.kickRefresh()
	time.Sleep(150 * time.Millisecond)

	remote := &config.Backend{
		URLPattern: "/_test",
		Host:       []string{realWriter.URL},
		ExtraConfig: config.ExtraConfig{
			BaseHANamespace: map[string]any{
				"service_dns": host,
				"port":        port,
			},
		},
	}
	p := newBaseHAProxy(remote, up)
	hdr := http.Header{
		"X-User-Id": []string{"user-z"},
		"X-Org-Id":  []string{"org-hanzo"},
		"X-Roles":   []string{"admin"},
	}
	if _, err := p(context.Background(), newHAProxyRequest(http.MethodPost, "/x", hdr, "{}")); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"X-User-Id": "user-z", "X-Org-Id": "org-hanzo", "X-Roles": "admin"} {
		if got := captured.Get(k); got != want {
			t.Fatalf("header %s: want %q, got %q", k, want, got)
		}
	}
}

// TestClientPinKeyComposition covers the read-your-writes client identity
// — same IP + same org must collide; different IP or different org must not.
func TestClientPinKeyComposition(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	cases := []struct {
		a, b    http.Header
		same    bool
	}{
		{h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-a"),
			h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-a"), true},
		{h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-a"),
			h("X-Forwarded-For", "1.2.3.5", "X-Org-Id", "org-a"), false},
		{h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-a"),
			h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-b"), false},
		// Multi-IP XFF — take the first (client's).
		{h("X-Forwarded-For", "1.2.3.4, 10.0.0.1", "X-Org-Id", "org-a"),
			h("X-Forwarded-For", "1.2.3.4", "X-Org-Id", "org-a"), true},
	}
	for i, c := range cases {
		ka := clientPinKey(c.a)
		kb := clientPinKey(c.b)
		got := ka == kb && ka != ""
		if got != c.same {
			t.Fatalf("case %d: a=%q b=%q got match=%v want %v", i, ka, kb, got, c.same)
		}
	}
}

func splitHostPort(hp string) (string, int) {
	host, ps, ok := strings.Cut(hp, ":")
	if !ok {
		return hp, 0
	}
	var p int
	_, _ = fmt.Sscanf(ps, "%d", &p)
	return host, p
}
