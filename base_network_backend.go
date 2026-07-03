//go:build legacy
// +build legacy

// Package gateway — base-network backend upstream.
//
// Implements `base-network://<service>` routing for base/network-enabled
// services (ATS, BD, TA, IAM, KMS, AML). See ~/work/hanzo/base/docs/NETWORK.md.
//
// Per-backend `extra_config`:
//
//	"github.com/hanzoai/gateway/base-network": {
//	  "shard_key":        "user_id",
//	  "shard_key_source": "jwt.sub"    // | jwt.owner | header:X-Shard | cookie:sid
//	}
//
// The enclosing backend's `host` names the headless Service whose members are
// polled at GET /-/base/members every 5 s. Writes route to a single
// rendezvous-hash owner pod; reads spread across the shard's member subset.
// A 307 from a pod we picked means the target isn't caught up — follow once.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	metric "github.com/luxfi/metric"
)

const BaseNetworkNamespace = "github.com/hanzoai/gateway/base-network"

type BaseNetworkConfig struct {
	ShardKey             string `json:"shard_key"`
	ShardKeySource       string `json:"shard_key_source"`
	MemberPollIntervalMS int    `json:"member_poll_interval_ms"`
}

type baseMember struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Shards []string `json:"shards"`
}

type baseMembersResponse struct {
	Members []baseMember `json:"members"`
}

// memberSnapshot is a read-only view used on the hot path. Built once per poll.
type memberSnapshot struct {
	members   []baseMember
	memberIdx map[string]int
	ring      []ringPoint // sorted by hash — consistent-hash fallback for N=1
}

type ringPoint struct {
	hash     uint32
	memberID string
}

func (s *memberSnapshot) empty() bool { return s == nil || len(s.members) == 0 }

// subsetFor returns members whose advertised prefix covers shardID. When no
// member advertises prefixes (N=1 singleton), the consistent-hash owner stands
// in so callers still have a target.
func (s *memberSnapshot) subsetFor(shardID string) []baseMember {
	if s.empty() {
		return nil
	}
	owners := make(map[string]struct{})
	for _, m := range s.members {
		for _, p := range m.Shards {
			if strings.HasPrefix(shardID, p) {
				owners[m.ID] = struct{}{}
				break
			}
		}
	}
	if len(owners) == 0 {
		if owner, ok := s.ownerFor(shardID); ok {
			return []baseMember{s.members[s.memberIdx[owner]]}
		}
		return nil
	}
	out := make([]baseMember, 0, len(owners))
	for id := range owners {
		out = append(out, s.members[s.memberIdx[id]])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ownerFor does a standard consistent-hash ring lookup.
func (s *memberSnapshot) ownerFor(shardID string) (string, bool) {
	if s.empty() || len(s.ring) == 0 {
		return "", false
	}
	h := hashShardID(shardID)
	i := sort.Search(len(s.ring), func(i int) bool { return s.ring[i].hash >= h })
	if i == len(s.ring) {
		i = 0
	}
	return s.ring[i].memberID, true
}

// hashShardID: crc32/Castagnoli. Stdlib, stable, well-distributed.
func hashShardID(s string) uint32 {
	return crc32.Checksum([]byte(s), crc32.MakeTable(crc32.Castagnoli))
}

func buildSnapshot(members []baseMember) *memberSnapshot {
	snap := &memberSnapshot{
		members:   members,
		memberIdx: make(map[string]int, len(members)),
	}
	for i, m := range members {
		snap.memberIdx[m.ID] = i
	}
	for _, m := range members {
		if len(m.Shards) == 0 {
			snap.ring = append(snap.ring, ringPoint{hash: hashShardID(m.ID), memberID: m.ID})
			continue
		}
		for _, p := range m.Shards {
			snap.ring = append(snap.ring, ringPoint{hash: hashShardID(p), memberID: m.ID})
		}
	}
	sort.Slice(snap.ring, func(i, j int) bool { return snap.ring[i].hash < snap.ring[j].hash })
	return snap
}

// memberCache: one poller per distinct service host.
type memberCache struct {
	host       string
	httpClient *http.Client
	interval   time.Duration
	logger     logging.Logger

	mu   sync.RWMutex
	snap *memberSnapshot

	stopOnce sync.Once
	stop     chan struct{}
}

func newMemberCache(host string, interval time.Duration, logger logging.Logger) *memberCache {
	c := &memberCache{
		host:       host,
		interval:   interval,
		logger:     logger,
		httpClient: &http.Client{Timeout: 3 * time.Second},
		stop:       make(chan struct{}),
	}
	c.refresh()
	go c.loop()
	return c
}

func (c *memberCache) loop() {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.refresh()
		case <-c.stop:
			return
		}
	}
}

func (c *memberCache) refresh() {
	metricMemberPolls.Inc()
	req, err := http.NewRequest(http.MethodGet, c.host+"/-/base/members", nil)
	if err != nil {
		c.logger.Error(fmt.Sprintf("[BACKEND: base-network] build members req %s: %v", c.host, err))
		return
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Warning(fmt.Sprintf("[BACKEND: base-network] poll %s: %v", c.host, err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.logger.Warning(fmt.Sprintf("[BACKEND: base-network] poll %s: status %d", c.host, resp.StatusCode))
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.logger.Warning(fmt.Sprintf("[BACKEND: base-network] read: %v", err))
		return
	}
	var parsed baseMembersResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		c.logger.Warning(fmt.Sprintf("[BACKEND: base-network] parse: %v", err))
		return
	}
	clean := parsed.Members[:0]
	for _, m := range parsed.Members {
		if m.ID == "" || m.URL == "" {
			continue
		}
		clean = append(clean, m)
	}
	snap := buildSnapshot(clean)
	c.mu.Lock()
	c.snap = snap
	c.mu.Unlock()
}

func (c *memberCache) snapshot() *memberSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

func (c *memberCache) close() {
	c.stopOnce.Do(func() { close(c.stop) })
}

// memberCachePool singletons caches per service host. Multiple endpoints
// pointing at the same base-network service share one poller.
var memberCachePool = struct {
	sync.Mutex
	caches map[string]*memberCache
}{caches: make(map[string]*memberCache)}

func getMemberCache(host string, interval time.Duration, logger logging.Logger) *memberCache {
	memberCachePool.Lock()
	defer memberCachePool.Unlock()
	if c, ok := memberCachePool.caches[host]; ok {
		return c
	}
	c := newMemberCache(host, interval, logger)
	memberCachePool.caches[host] = c
	return c
}

var (
	metricShardMismatches = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_network_shard_mismatches_total",
		Help: "Upstream 307s indicating stale shard→owner mapping.",
	})
	metricMemberPolls = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_network_member_polls_total",
		Help: "Total member-list poll attempts against base-network services.",
	})
	metric307 = metric.NewCounter(metric.CounterOpts{
		Name: "gateway_base_network_307_total",
		Help: "Total 307 redirects followed once to a peer pod.",
	})
)

func writeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// BaseNetworkBackendFactory wraps `next` and intercepts backends carrying a
// BaseNetworkNamespace extra_config block. All others fall through.
func BaseNetworkBackendFactory(logger logging.Logger, next proxy.BackendFactory) proxy.BackendFactory {
	return func(remote *config.Backend) proxy.Proxy {
		raw, ok := remote.ExtraConfig[BaseNetworkNamespace]
		if !ok {
			return next(remote)
		}
		b, err := json.Marshal(raw)
		if err != nil {
			logger.Error("[BACKEND: base-network] marshal config:", err.Error())
			return next(remote)
		}
		var cfg BaseNetworkConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			logger.Error("[BACKEND: base-network] parse config:", err.Error())
			return next(remote)
		}
		if len(remote.Host) == 0 {
			logger.Error("[BACKEND: base-network] no host configured")
			return next(remote)
		}
		if cfg.ShardKeySource == "" {
			logger.Error("[BACKEND: base-network] shard_key_source is required")
			return next(remote)
		}
		interval := 5 * time.Second
		if cfg.MemberPollIntervalMS > 0 {
			interval = time.Duration(cfg.MemberPollIntervalMS) * time.Millisecond
		}
		cache := getMemberCache(remote.Host[0], interval, logger)
		logger.Info(fmt.Sprintf("[BACKEND: base-network] routing %s via %s (key=%s, src=%s)",
			remote.URLPattern, remote.Host[0], cfg.ShardKey, cfg.ShardKeySource))
		return newBaseNetworkProxy(cfg, cache)
	}
}

func newBaseNetworkProxy(cfg BaseNetworkConfig, cache *memberCache) proxy.Proxy {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		// Never follow redirects automatically; 307 is a routing signal.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return func(ctx context.Context, req *proxy.Request) (*proxy.Response, error) {
		shardID := extractShardKey(cfg.ShardKeySource, req)
		if shardID == "" {
			return errorResponse(http.StatusBadRequest, `{"error":"shard_key_missing"}`), nil
		}
		snap := cache.snapshot()
		if snap.empty() {
			return errorResponse(http.StatusBadGateway, `{"error":"no_members"}`), nil
		}
		target, err := pickTarget(snap, shardID, req.Method)
		if err != nil {
			return errorResponse(http.StatusBadGateway, `{"error":"no_members"}`), nil
		}

		// Body is read once and replayed on 307 retry.
		var bodyBytes []byte
		if req.Body != nil {
			bb, err := io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("base-network: read body: %w", err)
			}
			bodyBytes = bb
		}

		resp, err := dispatch(ctx, httpClient, target, shardID, req, bodyBytes)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTemporaryRedirect {
			metric307.Inc()
			if loc := resp.Header.Get("Location"); loc != "" {
				metricShardMismatches.Inc()
				resp.Body.Close()
				resp2, err := dispatch(ctx, httpClient, loc, shardID, req, bodyBytes)
				if err != nil {
					return nil, err
				}
				if resp2.StatusCode == http.StatusTemporaryRedirect {
					resp2.Body.Close()
					return errorResponse(http.StatusBadGateway, `{"error":"redirect_loop"}`), nil
				}
				return responseFromHTTP(ctx, resp2), nil
			}
		}
		return responseFromHTTP(ctx, resp), nil
	}
}

// pickTarget selects the upstream URL. Writes use rendezvous-hash (HRW) within
// the shard's subset — stable under add/remove of non-winning members. Reads
// use a different seeded pick for spread while staying pinned per shard.
func pickTarget(snap *memberSnapshot, shardID, method string) (string, error) {
	subset := snap.subsetFor(shardID)
	if len(subset) == 0 {
		owner, ok := snap.ownerFor(shardID)
		if !ok {
			return "", errors.New("no members")
		}
		return snap.members[snap.memberIdx[owner]].URL, nil
	}
	if writeMethod(method) {
		bestIdx := 0
		bestHash := hashShardID(shardID + "|" + subset[0].ID)
		for i := 1; i < len(subset); i++ {
			h := hashShardID(shardID + "|" + subset[i].ID)
			if h < bestHash {
				bestHash = h
				bestIdx = i
			}
		}
		return subset[bestIdx].URL, nil
	}
	return subset[int(hashShardID(shardID+"|r"))%len(subset)].URL, nil
}

// dispatch issues one upstream request. Target is a fully-qualified pod URL.
func dispatch(ctx context.Context, c *http.Client, target, shardID string, req *proxy.Request, body []byte) (*http.Response, error) {
	fullURL := strings.TrimRight(target, "/") + req.Path
	if len(req.Query) > 0 {
		fullURL += "?" + req.Query.Encode()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	hreq, err := http.NewRequestWithContext(ctx, req.Method, fullURL, reader)
	if err != nil {
		return nil, fmt.Errorf("base-network: build request: %w", err)
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	hreq.Header.Set("X-Base-Shard", shardID)
	return c.Do(hreq)
}

// responseFromHTTP adapts an http.Response to a proxy.Response suitable for
// the no-op render path. Body streams through; headers (inc. Set-Cookie for
// txseq) are preserved.
func responseFromHTTP(ctx context.Context, r *http.Response) *proxy.Response {
	return &proxy.Response{
		Data:       map[string]interface{}{},
		IsComplete: r.StatusCode < http.StatusInternalServerError,
		Io:         proxy.NewReadCloserWrapper(ctx, r.Body),
		Metadata: proxy.Metadata{
			StatusCode: r.StatusCode,
			Headers:    r.Header,
		},
	}
}

func errorResponse(status int, body string) *proxy.Response {
	return &proxy.Response{
		Data:       map[string]interface{}{},
		IsComplete: status < http.StatusInternalServerError,
		Io:         io.NopCloser(strings.NewReader(body)),
		Metadata: proxy.Metadata{
			StatusCode: status,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
		},
	}
}

// extractShardKey reads the shard key per source spec. Returns "" when absent.
//
//	jwt.sub       → X-User-Id     (injected by auth_middleware)
//	jwt.owner     → X-Org-Id      (injected by auth_middleware)
//	jwt.<other>   → not supported (auth_middleware doesn't propagate)
//	header:<Name> → raw header
//	cookie:<name> → cookie value
func extractShardKey(src string, req *proxy.Request) string {
	switch {
	case src == "jwt.sub":
		return firstHeader(req.Headers, "X-User-Id")
	case src == "jwt.owner":
		return firstHeader(req.Headers, "X-Org-Id")
	case strings.HasPrefix(src, "jwt."):
		return ""
	case strings.HasPrefix(src, "header:"):
		return firstHeader(req.Headers, strings.TrimPrefix(src, "header:"))
	case strings.HasPrefix(src, "cookie:"):
		return readCookie(req.Headers, strings.TrimPrefix(src, "cookie:"))
	}
	return ""
}

func firstHeader(h map[string][]string, name string) string {
	for _, k := range []string{name, strings.ToLower(name), http.CanonicalHeaderKey(name)} {
		if vs, ok := h[k]; ok && len(vs) > 0 && vs[0] != "" {
			return vs[0]
		}
	}
	return ""
}

func readCookie(h map[string][]string, name string) string {
	raw := firstHeader(h, "Cookie")
	if raw == "" {
		return ""
	}
	req := http.Request{Header: http.Header{"Cookie": []string{raw}}}
	if c, err := req.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}
