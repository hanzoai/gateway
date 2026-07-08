package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCookieDomainFor_PerApex(t *testing.T) {
	cases := map[string]string{
		"studio.hanzo.ai":   ".hanzo.ai",
		"console.hanzo.ai":  ".hanzo.ai",
		"hanzo.ai":          ".hanzo.ai",
		"hanzo.app":         ".hanzo.app",
		"hanzo.chat":        ".hanzo.chat",
		"app.hanzo.app:443": ".hanzo.app",
		"CHAT.HANZO.AI":     ".hanzo.ai",
		"localhost":         "",
	}
	for host, want := range cases {
		if got := cookieDomainFor(host); got != want {
			t.Errorf("cookieDomainFor(%q) = %q, want %q", host, got, want)
		}
	}
}

// modeServer stubs cloud's GET /v1/featuregate/mode, counting calls.
func modeServer(t *testing.T, waitlistMode, known bool, calls *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host":         r.URL.Query().Get("host"),
			"waitlistMode": waitlistMode,
			"known":        known,
		})
	}))
}

func TestCarriesAPIKey(t *testing.T) {
	mk := func(set func(h http.Header)) *http.Request {
		r := httptest.NewRequest("GET", "http://api.hanzo.ai/v1/chat/completions", nil)
		set(r.Header)
		return r
	}
	yes := []*http.Request{
		mk(func(h http.Header) { h.Set("Authorization", "Bearer hk-43f50b6b") }),
		mk(func(h http.Header) { h.Set("Authorization", "bearer sk-hz-abc") }),
		mk(func(h http.Header) { h.Set("Authorization", "Bearer pk-hz-obs") }),
		mk(func(h http.Header) { h.Set("Authorization", "Bearer fw_live_x") }),
		mk(func(h http.Header) { h.Set("X-Forwarded-Authorization", "Bearer hz_secret") }),
		mk(func(h http.Header) { h.Set("api-key", "hk-headerform") }),
		mk(func(h http.Header) { h.Set("X-Api-Key", "sk-hz-x") }),
	}
	for i, r := range yes {
		if !carriesAPIKey(r) {
			t.Fatalf("case %d: expected API key detected", i)
		}
	}
	no := []*http.Request{
		mk(func(h http.Header) {}),
		mk(func(h http.Header) { h.Set("Authorization", "Bearer eyJhbGciOi.jwt.sig") }), // a JWT is NOT a key
		mk(func(h http.Header) { h.Set("Authorization", "Basic dXNlcjpwYXNz") }),
	}
	for i, r := range no {
		if carriesAPIKey(r) {
			t.Fatalf("negative case %d: API key wrongly detected", i)
		}
	}
}

func TestModeCache_OpenService_NotGated(t *testing.T) {
	var calls int32
	srv := modeServer(t, false, true, &calls) // known + mode off = OPEN
	defer srv.Close()
	m := newModeCache(srv.URL, time.Minute)
	if m.gated(context.Background(), "hanzo.chat") {
		t.Fatal("known service with mode off should NOT be gated")
	}
}

func TestModeCache_GatedService(t *testing.T) {
	var calls int32
	srv := modeServer(t, true, true, &calls) // known + mode on = GATED
	defer srv.Close()
	m := newModeCache(srv.URL, time.Minute)
	if !m.gated(context.Background(), "hanzo.chat") {
		t.Fatal("known service with mode on should be gated")
	}
}

func TestModeCache_UnknownHost_FailSafeGated(t *testing.T) {
	var calls int32
	srv := modeServer(t, false, false, &calls) // unknown host
	defer srv.Close()
	m := newModeCache(srv.URL, time.Minute)
	if !m.gated(context.Background(), "surprise.hanzo.ai") {
		t.Fatal("an un-governed host must fail SAFE to gated")
	}
}

func TestModeCache_Caches(t *testing.T) {
	var calls int32
	srv := modeServer(t, false, true, &calls)
	defer srv.Close()
	m := newModeCache(srv.URL, time.Minute)
	for i := 0; i < 3; i++ {
		m.gated(context.Background(), "hanzo.chat")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("registry calls = %d, want 1 (cached)", got)
	}
}

func TestModeCache_ServerError_FailSafeGated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	m := newModeCache(srv.URL, time.Minute)
	if !m.gated(context.Background(), "hanzo.chat") {
		t.Fatal("registry error with no cache must fail SAFE to gated")
	}
}

func TestModeCache_ServesStaleOnError(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"waitlistMode": false, "known": true})
	}))
	defer srv.Close()
	m := newModeCache(srv.URL, time.Nanosecond) // entries expire immediately

	// Warm the cache with an OPEN verdict.
	if m.gated(context.Background(), "hanzo.chat") {
		t.Fatal("warm: should be open")
	}
	// Now the registry fails; the fresh cache is expired, so gated() must serve the
	// last-known OPEN verdict rather than flip the service closed on a blip.
	fail.Store(true)
	time.Sleep(time.Millisecond)
	if m.gated(context.Background(), "hanzo.chat") {
		t.Fatal("error path should serve the stale last-known OPEN verdict")
	}
}
