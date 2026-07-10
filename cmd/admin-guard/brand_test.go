// Copyright 2023-2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRegistrableDomain is gap #1: the guard cookie is scoped to the REGISTRABLE
// domain of each request's host, so one binary white-labels every brand instead
// of pinning ".hanzo.ai" (which a browser on admin.zoo.cloud silently drops).
func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"admin.hanzo.ai":      ".hanzo.ai",
		"functions.hanzo.ai":  ".hanzo.ai",
		"admin.zoo.cloud":     ".zoo.cloud",
		"admin.lux.network":   ".lux.network",
		"hanzo.ai":            ".hanzo.ai",
		"admin.zoo.cloud:443": ".zoo.cloud", // port stripped
		"localhost":           "",           // single label → host-only cookie
	}
	for host, want := range cases {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q)=%q want %q", host, got, want)
		}
	}
}

// TestConsoleFor is the non-admin brand-routing half: zoo→zoo console,
// lux→lux console, unknown→default. Lux's console is on lux.cloud, not
// lux.network — the derivation keys off the guarded host's registrable domain.
func TestConsoleFor(t *testing.T) {
	c := testConfig()
	cases := map[string]string{
		"admin.hanzo.ai":     "https://console.hanzo.ai",
		"functions.hanzo.ai": "https://console.hanzo.ai",
		"admin.zoo.cloud":    "https://console.zoo.cloud",
		"admin.lux.network":  "https://console.lux.cloud",
		"admin.example.test": "https://console.hanzo.ai", // unknown → default
	}
	for host, want := range cases {
		if got := c.consoleFor(host); got != want {
			t.Errorf("consoleFor(%q)=%q want %q", host, got, want)
		}
	}
}

// TestBrandCookieDomainAndConsole exercises the live forward-auth paths per
// brand: (a) an anonymous browser gets the PKCE state cookie scoped to ITS host's
// registrable domain (so it sticks and the callback can read it), and (b) an
// authenticated non-admin is bounced to ITS brand's console. Admin is global —
// an admin cookie is allowed on every brand host.
func TestBrandCookieDomainAndConsole(t *testing.T) {
	cfg := testConfig()
	brands := []struct {
		host          string
		wantCookieDom string
		wantConsole   string
	}{
		{"admin.hanzo.ai", "hanzo.ai", "https://console.hanzo.ai"},
		{"admin.zoo.cloud", "zoo.cloud", "https://console.zoo.cloud"},
		{"admin.lux.network", "lux.network", "https://console.lux.cloud"},
	}

	for _, b := range brands {
		t.Run(b.host+"/anon-state-cookie", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", b.host)
			r.Header.Set("X-Forwarded-Uri", "/")
			r.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()
			cfg.handleVerify(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("anon browser: status=%d want 302", w.Code)
			}
			// redirect_uri must point back at THIS host's callback (gap #2:
			// each such URI must be registered on the IAM app).
			loc := w.Header().Get("Location")
			wantRU := "redirect_uri=https%3A%2F%2F" + b.host + "%2F__guard%2Fcallback"
			if !strings.Contains(loc, wantRU) {
				t.Errorf("authorize redirect_uri wrong for %s:\n  loc=%s", b.host, loc)
			}
			// The state cookie MUST be scoped to this host's registrable domain,
			// or the browser drops it and login loops.
			var state *http.Cookie
			for _, ck := range w.Result().Cookies() {
				if ck.Name == stateCookie {
					state = ck
				}
			}
			if state == nil {
				t.Fatal("no state cookie set")
			}
			if state.Domain != b.wantCookieDom {
				t.Errorf("state cookie Domain=%q want %q (browser on %s would drop a foreign-domain cookie)", state.Domain, b.wantCookieDom, b.host)
			}
		})

		t.Run(b.host+"/nonadmin-console", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
			r.Header.Set("X-Forwarded-Host", b.host)
			r.Header.Set("Accept", "text/html")
			r.AddCookie(cfg.guardCookie("acme")) // authed, non-admin
			w := httptest.NewRecorder()
			cfg.handleVerify(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("non-admin: status=%d want 302", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != b.wantConsole {
				t.Errorf("non-admin on %s → %q want %q (brand console)", b.host, loc, b.wantConsole)
			}
		})

		t.Run(b.host+"/admin-allow", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
			r.Header.Set("X-Forwarded-Host", b.host)
			r.Header.Set("Accept", "text/html")
			r.AddCookie(cfg.guardCookie("admin")) // global admin
			w := httptest.NewRecorder()
			cfg.handleVerify(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("admin on %s: status=%d want 204 (global admin allowed on every brand)", b.host, w.Code)
			}
		})
	}
}
