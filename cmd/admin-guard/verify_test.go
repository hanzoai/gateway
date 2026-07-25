// Copyright 2023-2025 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/gateway/v2/iamauth"
)

// testConfig builds a guard config with a fixed HMAC key and no live IAM
// dependency. The validator is constructed but never hit on the cookie/anonymous
// paths exercised here (no Bearer token ⇒ iamauth returns ErrNoToken).
func testConfig() *config {
	return &config{
		adminOrg:       "admin",
		consoles:       parseBrandMap(defaultConsoleMap),
		defaultConsole: "https://console.hanzo.ai",
		iamPublic:      "https://hanzo.id",
		clientID:       "hanzo-admin-guard",
		cookieName:     "hanzo_admin_guard",
		cookieTTL:      8 * time.Hour,
		hmacKey:        []byte("0123456789abcdef-test-key"),
		validator:      iamauth.NewValidator(iamauth.ConfigFromEnv()),
	}
}

// guardCookie returns a valid, unexpired guard session cookie for a principal
// (owner + org-admin bit), in the canonical owner|isAdmin|exp form.
func (c *config) guardCookie(owner string, isAdmin bool) *http.Cookie {
	payload := fmt.Sprintf("%s|%s|%d", owner, sessionBit(isAdmin), time.Now().Add(time.Hour).Unix())
	return &http.Cookie{Name: c.cookieName, Value: c.sign(payload)}
}

// TestVerifyContentNegotiation is the admin-guard forward-auth contract on a
// GLOBAL surface (platform.hanzo.ai — not a tenant admin.<brand> host, so only
// platform-sudo passes): three verdicts, content-negotiated for API vs browser
// callers. Global admin → 204; authenticated non-admin → 403 for API,
// 302→console for a browser; no identity → 401 for API, 302→IAM-login for a
// browser. A non-admin is NEVER allowed through, and an API caller is never
// bounced through an interactive redirect. (Tenant-scoped allow/deny is covered
// in tenant_test.go.)
func TestVerifyContentNegotiation(t *testing.T) {
	cfg := testConfig()

	cases := []struct {
		name         string
		cookie       *http.Cookie
		accept       string // Accept header (browser sends text/html)
		bearer       string // presence marks an API client even with html Accept
		wantStatus   int
		wantLocation string // expected redirect target prefix (for 302s)
		wantBody     string // expected body substring (for 401/403)
	}{
		{
			name:       "admin cookie → 204 allow",
			cookie:     cfg.guardCookie("admin", true),
			accept:     "text/html",
			wantStatus: http.StatusNoContent,
		},
		{
			name:         "non-admin cookie + browser → 302 console",
			cookie:       cfg.guardCookie("acme", false),
			accept:       "text/html",
			wantStatus:   http.StatusFound,
			wantLocation: "https://console.hanzo.ai",
		},
		{
			name:       "non-admin cookie + API (json) → 403",
			cookie:     cfg.guardCookie("acme", false),
			accept:     "application/json",
			wantStatus: http.StatusForbidden,
			wantBody:   "admin access required",
		},
		{
			name:       "non-admin cookie + Bearer → 403 (API even with html accept)",
			cookie:     cfg.guardCookie("acme", false),
			accept:     "text/html",
			bearer:     "some-token",
			wantStatus: http.StatusForbidden,
			wantBody:   "admin access required",
		},
		{
			name:       "anonymous + API (json) → 401",
			accept:     "application/json",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "authentication required",
		},
		{
			name:         "anonymous + browser → 302 IAM login",
			accept:       "text/html",
			wantStatus:   http.StatusFound,
			wantLocation: "https://hanzo.id/v1/iam/oauth/authorize",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "platform.hanzo.ai")
			r.Header.Set("X-Forwarded-Uri", "/admin")
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			if tc.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			w := httptest.NewRecorder()

			cfg.handleVerify(w, r)

			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d; body=%s loc=%s", w.Code, tc.wantStatus, w.Body.String(), w.Header().Get("Location"))
			}
			if tc.wantStatus == http.StatusNoContent {
				if w.Header().Get("X-Admin-Guard") != "allow" {
					t.Errorf("admin allow: missing X-Admin-Guard=allow header")
				}
				if w.Header().Get("X-Org-Id") != "admin" {
					t.Errorf("admin allow: X-Org-Id=%q want admin", w.Header().Get("X-Org-Id"))
				}
			}
			if tc.wantLocation != "" {
				if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, tc.wantLocation) {
					t.Errorf("redirect Location=%q, want prefix %q", loc, tc.wantLocation)
				}
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Errorf("body=%q, want substring %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestVerifyRejectsTamperedCookie asserts a forged/edited guard cookie does not
// authenticate: the HMAC check fails, so a tampered admin claim is treated as no
// identity (→ 401 for an API caller), never allowed through.
func TestVerifyRejectsTamperedCookie(t *testing.T) {
	cfg := testConfig()
	good := cfg.guardCookie("admin", true)
	tampered := &http.Cookie{Name: cfg.cookieName, Value: good.Value + "x"}

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("Accept", "application/json")
	r.AddCookie(tampered)
	w := httptest.NewRecorder()

	cfg.handleVerify(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered admin cookie: status=%d want 401 (must not authenticate)", w.Code)
	}
}

// TestVerifyRejectsExpiredCookie asserts an expired (but correctly-signed) guard
// cookie is rejected — time-bounded sessions, no replay past expiry.
func TestVerifyRejectsExpiredCookie(t *testing.T) {
	cfg := testConfig()
	expired := &http.Cookie{Name: cfg.cookieName, Value: cfg.sign(fmt.Sprintf("admin|1|%d", time.Now().Add(-time.Hour).Unix()))}

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("Accept", "application/json")
	r.AddCookie(expired)
	w := httptest.NewRecorder()

	cfg.handleVerify(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired admin cookie: status=%d want 401 (must not authenticate past expiry)", w.Code)
	}
}
