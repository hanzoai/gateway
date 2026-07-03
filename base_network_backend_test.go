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
	"sync/atomic"
	"testing"
	"time"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
)

// -----------------------------------------------------------------------------
// Consistent-hash routing — unit tests
// -----------------------------------------------------------------------------

func TestOwnerForIsDeterministic(t *testing.T) {
	snap := buildSnapshot([]baseMember{
		{ID: "pod-0", URL: "http://pod-0:8090", Shards: []string{"0000", "ffff"}},
		{ID: "pod-1", URL: "http://pod-1:8090", Shards: []string{"5555", "aaaa"}},
		{ID: "pod-2", URL: "http://pod-2:8090", Shards: []string{"3333", "cccc"}},
	})
	// Stable mapping across calls.
	owners := make(map[string]string)
	for _, s := range []string{"0000-user-a", "5555-user-b", "ffff-user-c", "aaaa-user-d"} {
		o, ok := snap.ownerFor(s)
		if !ok {
			t.Fatalf("no owner for %s", s)
		}
		owners[s] = o
	}
	for s, want := range owners {
		got, _ := snap.ownerFor(s)
		if got != want {
			t.Fatalf("non-deterministic: %s got %s want %s", s, got, want)
		}
	}
}

// TestOwnerForMonotonicRemoval verifies the core consistent-hash property:
// removing a member only disturbs the shards it owned. Keys owned by survivors
// must keep the same owner.
func TestOwnerForMonotonicRemoval(t *testing.T) {
	full := []baseMember{
		{ID: "pod-0", URL: "http://pod-0:8090", Shards: []string{"0000", "ffff"}},
		{ID: "pod-1", URL: "http://pod-1:8090", Shards: []string{"5555", "aaaa"}},
		{ID: "pod-2", URL: "http://pod-2:8090", Shards: []string{"3333", "cccc"}},
	}
	snapFull := buildSnapshot(full)

	// Generate a corpus of shard IDs, record owners under the full ring.
	keys := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		keys = append(keys, fmt.Sprintf("user-%d", i))
	}
	initial := make(map[string]string, len(keys))
	for _, k := range keys {
		o, _ := snapFull.ownerFor(k)
		initial[k] = o
	}

	// Remove pod-1 and rebuild.
	reduced := []baseMember{full[0], full[2]}
	snapRed := buildSnapshot(reduced)

	moved := 0
	for _, k := range keys {
		after, _ := snapRed.ownerFor(k)
		before := initial[k]
		if before == "pod-1" {
			// Must redistribute to one of the survivors.
			if after != "pod-0" && after != "pod-2" {
				t.Fatalf("removed pod's key %s went to %s (not a survivor)", k, after)
			}
			moved++
			continue
		}
		if after != before {
			t.Fatalf("key %s was owned by %s, moved to %s after removing pod-1", k, before, after)
		}
	}
	t.Logf("removal redistributed %d/%d keys (only pod-1's)", moved, len(keys))
	if moved == 0 {
		t.Fatal("expected at least some keys previously owned by pod-1")
	}
}

func TestSubsetForFallbackToOwner(t *testing.T) {
	// Member advertises no prefixes → subsetFor should fall back to the
	// consistent-hash owner (singleton behaviour, N=1).
	snap := buildSnapshot([]baseMember{
		{ID: "pod-0", URL: "http://pod-0:8090"},
	})
	got := snap.subsetFor("any-shard")
	if len(got) != 1 || got[0].ID != "pod-0" {
		t.Fatalf("expected pod-0 fallback, got %+v", got)
	}
}

func TestExtractShardKey(t *testing.T) {
	cases := []struct {
		src     string
		headers map[string][]string
		want    string
	}{
		{"jwt.sub", map[string][]string{"X-User-Id": {"alice"}}, "alice"},
		{"jwt.owner", map[string][]string{"X-Org-Id": {"hanzo"}}, "hanzo"},
		{"header:X-Shard", map[string][]string{"X-Shard": {"abc"}}, "abc"},
		{"cookie:sid", map[string][]string{"Cookie": {"sid=deadbeef; other=1"}}, "deadbeef"},
		{"jwt.sub", map[string][]string{}, ""},
		{"jwt.unknown_claim", map[string][]string{"X-Anything": {"x"}}, ""},
	}
	for _, tc := range cases {
		got := extractShardKey(tc.src, &proxy.Request{Headers: tc.headers})
		if got != tc.want {
			t.Errorf("extractShardKey(%q): got %q want %q", tc.src, got, tc.want)
		}
	}
}

func TestWriteMethod(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "post"} {
		if !writeMethod(m) {
			t.Errorf("%s should be a write", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", ""} {
		if writeMethod(m) {
			t.Errorf("%s should not be a write", m)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration — 3 fake pods, membership endpoint, gateway proxy
// -----------------------------------------------------------------------------

// pod is a fake base-network pod. Counts requests by method.
type pod struct {
	id     string
	url    string
	shards []string
	writes atomic.Int64
	reads  atomic.Int64
}

// buildFakeNetwork spins up N pod servers + a members endpoint. Returns the
// members server URL (the backend "host") and a cleanup that also drops the
// memberCachePool so tests don't leak state.
func buildFakeNetwork(t *testing.T, pods []*pod) (string, func()) {
	t.Helper()
	servers := make([]*httptest.Server, 0, len(pods))
	for _, p := range pods {
		p := p
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if writeMethod(r.Method) {
				p.writes.Add(1)
			} else {
				p.reads.Add(1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pod":"` + p.id + `"}`))
		}))
		p.url = s.URL
		servers = append(servers, s)
	}
	members := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/-/base/members" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := baseMembersResponse{}
		for _, p := range pods {
			resp.Members = append(resp.Members, baseMember{ID: p.id, URL: p.url, Shards: p.shards})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return members.URL, func() {
		for _, s := range servers {
			s.Close()
		}
		members.Close()
		memberCachePool.Lock()
		for k, c := range memberCachePool.caches {
			c.close()
			delete(memberCachePool.caches, k)
		}
		memberCachePool.Unlock()
	}
}

// waitForMembers blocks until the cache for `host` has populated or deadline.
func waitForMembers(t *testing.T, host string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		memberCachePool.Lock()
		c := memberCachePool.caches[host]
		memberCachePool.Unlock()
		if c != nil && c.snapshot() != nil && !c.snapshot().empty() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("member cache not populated for %s", host)
}

func TestBaseNetworkRoutingWritesReads(t *testing.T) {
	pods := []*pod{
		{id: "pod-0", shards: []string{"0"}},
		{id: "pod-1", shards: []string{"1"}},
		{id: "pod-2", shards: []string{"2"}},
	}
	host, cleanup := buildFakeNetwork(t, pods)
	defer cleanup()

	remote := &config.Backend{
		URLPattern: "/v1/rows",
		Host:       []string{host},
		ExtraConfig: config.ExtraConfig{
			BaseNetworkNamespace: map[string]interface{}{
				"shard_key":               "user_id",
				"shard_key_source":        "jwt.sub",
				"member_poll_interval_ms": 100,
			},
		},
	}
	p := BaseNetworkBackendFactory(logging.NoOp, func(*config.Backend) proxy.Proxy {
		return func(context.Context, *proxy.Request) (*proxy.Response, error) {
			t.Fatal("fallthrough reached; base-network block not matched")
			return nil, nil
		}
	})(remote)
	waitForMembers(t, host)

	// Disjoint prefixes: "0-user-a" → pod-0, "1-..." → pod-1, "2-..." → pod-2.
	writesByPod := map[string]string{"pod-0": "0-user-a", "pod-1": "1-user-b", "pod-2": "2-user-c"}
	for wantPod, user := range writesByPod {
		resp, err := p(context.Background(), newProxyRequest("POST", "/v1/rows", user, nil))
		if err != nil || resp.Metadata.StatusCode != http.StatusOK {
			t.Fatalf("write %s: err=%v status=%d", user, err, resp.Metadata.StatusCode)
		}
		body, _ := io.ReadAll(resp.Io)
		if !strings.Contains(string(body), wantPod) {
			t.Fatalf("write for %s landed on wrong pod: %s", user, body)
		}
	}
	for _, p := range pods {
		if got := p.writes.Load(); got != 1 {
			t.Errorf("pod %s: got %d writes, want 1", p.id, got)
		}
	}

	// Reads: singleton subsets (disjoint prefixes) pin to the same owner.
	for wantPod, user := range writesByPod {
		resp, err := p(context.Background(), newProxyRequest("GET", "/v1/rows/1", user, nil))
		if err != nil || resp.Metadata.StatusCode != http.StatusOK {
			t.Fatalf("read %s: err=%v status=%d", user, err, resp.Metadata.StatusCode)
		}
		body, _ := io.ReadAll(resp.Io)
		if !strings.Contains(string(body), wantPod) {
			t.Fatalf("read for %s hit wrong pod: %s", user, body)
		}
	}

	// Shard key missing → 400, no dispatch.
	startTotal := totalReads(pods) + totalWrites(pods)
	resp, err := p(context.Background(), newProxyRequest("GET", "/v1/rows", "", nil))
	if err != nil {
		t.Fatalf("missing shard: unexpected err %v", err)
	}
	if resp.Metadata.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing shard: expected 400, got %d", resp.Metadata.StatusCode)
	}
	if got := totalReads(pods) + totalWrites(pods); got != startTotal {
		t.Fatalf("missing shard should not dispatch; total changed %d→%d", startTotal, got)
	}
}

func TestBaseNetwork307FollowOnce(t *testing.T) {
	// Pod A always 307s to pod B; gateway follows exactly once.
	aHits, bHits := atomic.Int64{}, atomic.Int64{}
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pod":"B"}`))
	}))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		aHits.Add(1)
		w.Header().Set("Location", b.URL+"/v1/rows")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer a.Close()
	members := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(baseMembersResponse{Members: []baseMember{
			{ID: "A", URL: a.URL, Shards: []string{"x"}},
		}})
	}))
	defer members.Close()
	defer func() {
		memberCachePool.Lock()
		for k, c := range memberCachePool.caches {
			c.close()
			delete(memberCachePool.caches, k)
		}
		memberCachePool.Unlock()
	}()

	remote := &config.Backend{
		URLPattern: "/v1/rows",
		Host:       []string{members.URL},
		ExtraConfig: config.ExtraConfig{
			BaseNetworkNamespace: map[string]interface{}{
				"shard_key":               "user_id",
				"shard_key_source":        "jwt.sub",
				"member_poll_interval_ms": 100,
			},
		},
	}
	p := BaseNetworkBackendFactory(logging.NoOp, func(*config.Backend) proxy.Proxy {
		return func(context.Context, *proxy.Request) (*proxy.Response, error) { return nil, nil }
	})(remote)
	waitForMembers(t, members.URL)

	resp, err := p(context.Background(), newProxyRequest("POST", "/v1/rows", "x-user", nil))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Metadata.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.Metadata.StatusCode)
	}
	if aHits.Load() != 1 || bHits.Load() != 1 {
		t.Fatalf("hits A=%d B=%d, want 1/1", aHits.Load(), bHits.Load())
	}
}

func newProxyRequest(method, path, user string, body io.Reader) *proxy.Request {
	h := map[string][]string{}
	if user != "" {
		h["X-User-Id"] = []string{user}
	}
	u, _ := url.Parse(path)
	var rc io.ReadCloser
	if body != nil {
		rc = io.NopCloser(body)
	}
	return &proxy.Request{
		Method: method, URL: u, Path: path,
		Query: url.Values{}, Headers: h, Body: rc,
	}
}

func totalReads(pods []*pod) int64 {
	var n int64
	for _, p := range pods {
		n += p.reads.Load()
	}
	return n
}
func totalWrites(pods []*pod) int64 {
	var n int64
	for _, p := range pods {
		n += p.writes.Load()
	}
	return n
}
