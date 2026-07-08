package main

// mode.go makes the @file waitlist-guard registry-driven: instead of gating purely
// by being ATTACHED to a router (the crude original — a service could only be opened
// by detaching the guard via an ingress edit), the guard now consults the CENTRAL
// feature-gate registry (cloud's GET /v1/featuregate/mode?host=<h>) at runtime, so a
// single admin toggle on admin.hanzo.ai governs it too — no ingress edit, no redeploy.
//
// It is the SAME registry the native cloud middleware (featuregate.Enforce) reads, so
// there is ONE source of truth for waitlist mode across both enforcement points.
//
// Reads are cached with a short TTL (a toggle takes effect within one TTL). FAIL-SAFE:
// the guard is attached ONLY to hosts that must default to gated, so a registry error
// or an unknown host resolves to GATED (serve stale-if-known, else gate) — an outage
// never accidentally OPENS a waitlisted service. This is orthogonal to the approval
// path's fail-OPEN-on-IAM-5xx (availability of an already-open door), and the two are
// deliberately different: mode governs whether the door exists; approval governs who
// walks through it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// modeCache resolves whether a host is in waitlist mode, cached with a short TTL.
type modeCache struct {
	url    string // cloud featuregate base, e.g. http://cloud-api.hanzo.svc.cluster.local:8000
	ttl    time.Duration
	client *http.Client

	mu    sync.Mutex
	cache map[string]modeEntry
}

type modeEntry struct {
	gated bool
	at    time.Time
}

func newModeCache(url string, ttl time.Duration) *modeCache {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &modeCache{
		url:    strings.TrimRight(url, "/"),
		ttl:    ttl,
		client: &http.Client{Timeout: 5 * time.Second},
		cache:  map[string]modeEntry{},
	}
}

// gated reports whether host is in waitlist mode (should be gated). It caches for
// ttl; on a miss it queries GET {url}/v1/featuregate/mode?host=. A host is OPEN
// only when the registry KNOWS it AND its waitlistMode is false; every other
// outcome (unknown host, registry error with no fresh cache) is GATED — the
// fail-safe default for a deliberately-attached guard. On a fetch error a
// stale-but-known cache entry is served (any age) before falling back to gated.
func (m *modeCache) gated(ctx context.Context, host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return true
	}
	if e, ok := m.fresh(h); ok {
		return e.gated
	}
	gated, ok := m.fetch(ctx, h)
	if ok {
		m.put(h, gated)
		return gated
	}
	// Fetch failed — serve a stale entry if we ever learned this host, else gate.
	if e, ok := m.any(h); ok {
		return e.gated
	}
	return true
}

func (m *modeCache) fetch(ctx context.Context, host string) (gated bool, ok bool) {
	if m.url == "" {
		return true, false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.url+"/v1/featuregate/mode?host="+url.QueryEscape(host), nil)
	if err != nil {
		return true, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return true, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return true, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return true, false
	}
	var out struct {
		WaitlistMode bool `json:"waitlistMode"`
		Known        bool `json:"known"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return true, false
	}
	// OPEN only when the registry knows the host and it is not in waitlist mode.
	return !(out.Known && !out.WaitlistMode), true
}

func (m *modeCache) fresh(host string) (modeEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.cache[host]
	if !ok || time.Since(e.at) > m.ttl {
		return modeEntry{}, false
	}
	return e, true
}

func (m *modeCache) any(host string) (modeEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.cache[host]
	return e, ok
}

func (m *modeCache) put(host string, gated bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[host] = modeEntry{gated: gated, at: time.Now()}
}

// normalizeHost mirrors featuregate.NormalizeHost: lowercased, trimmed, port
// stripped, so the guard and the registry agree on the lookup key.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// hostOf resolves the guarded host from the ingress-forwarded headers (the same
// source originalURL uses), falling back to the request Host.
func hostOf(r *http.Request) string {
	return firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
}

// apiKeyPrefixes are the Hanzo API-key prefixes (mirrors cloud auth_identity.go
// isAPIKey — the ONE authority). A token with one of these is possession-gated, not
// a session principal.
var apiKeyPrefixes = []string{"hk-", "sk-", "pk-", "fw_", "hz_"}

// carriesAPIKey reports whether the request authenticates with a Hanzo API key
// (Authorization: Bearer <key>, or the api-key/x-api-key headers). A key request is
// possession-gated + billed downstream, NEVER waitlist-gated — this is the same
// MONEY-CRITICAL exemption the native cloud middleware applies, kept here so the
// interim guard can never bounce a paid-inference call even if it is ever attached
// to an API host. The ingress may strip the caller's Authorization into
// X-Forwarded-Authorization; check both.
func carriesAPIKey(r *http.Request) bool {
	auth := firstNonEmpty(
		strings.TrimSpace(r.Header.Get("Authorization")),
		strings.TrimSpace(r.Header.Get("X-Forwarded-Authorization")),
	)
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") && hasAPIKeyPrefix(strings.TrimSpace(auth[7:])) {
		return true
	}
	return hasAPIKeyPrefix(strings.TrimSpace(r.Header.Get("api-key"))) ||
		hasAPIKeyPrefix(strings.TrimSpace(r.Header.Get("X-Api-Key")))
}

func hasAPIKeyPrefix(tok string) bool {
	for _, p := range apiKeyPrefixes {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	return false
}

// cookieDomainFor derives the guard/session cookie Domain from the REGISTRABLE
// domain (eTLD+1) of the request host, PER REQUEST — never a single static value.
// The control plane gates services across MULTIPLE apexes (hanzo.ai / hanzo.app /
// hanzo.chat / studio.hanzo.ai), and a browser REJECTS a cookie whose Domain is not
// a suffix of the request host — so a static `.hanzo.ai` breaks PKCE login on
// hanzo.app ("missing state cookie"). The last-two-labels heuristic is exact for
// every Hanzo/brand apex (all are two-label registrable domains: hanzo.ai/.app/.chat,
// lux.network, zoo.ngo, pars.network): studio.hanzo.ai → .hanzo.ai (SSO shared
// across *.hanzo.ai), hanzo.app → .hanzo.app. Returns "" for a bare/one-label host
// (localhost) so the caller falls back to a host-only cookie.
func cookieDomainFor(host string) string {
	h := normalizeHost(host)
	labels := strings.Split(h, ".")
	if len(labels) < 2 || labels[len(labels)-1] == "" {
		return ""
	}
	return "." + strings.Join(labels[len(labels)-2:], ".")
}
