// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// authn_policy_test.go covers the AUTHENTICATED surface class (/__guard/verify-authn),
// which exists so a per-org surface like ci.hanzo.ai can be reachable by its
// users instead of by global sudo alone.
//
// The properties that matter are a matched pair, and both are asserted here:
// the new policy must ADMIT a plain org user, and the old policy must still
// REFUSE that same user on that same host. A change that only proved the first
// would be indistinguishable from having quietly loosened every admin surface.

// ciRequest builds a verify request as the ingress presents it for ci.hanzo.ai —
// deliberately NOT an admin.<brand> host, so tenantOrgForHost() returns
// ("", false) and adminPolicy admits global sudo only.
func ciRequest(accept string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify-authn", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "ci.hanzo.ai")
	r.Header.Set("X-Forwarded-Uri", "/")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	for _, ck := range cookies {
		r.AddCookie(ck)
	}
	return r
}

// TestAuthnPolicyAdmitsPlainOrgUser is the whole point of the policy: a user
// whose home org is `lux` and who is NOT an admin anywhere reaches ci.hanzo.ai,
// and the guard writes X-Org-Id=lux so the dashboard scopes to lux's builds.
func TestAuthnPolicyAdmitsPlainOrgUser(t *testing.T) {
	cfg := testConfig()
	w := httptest.NewRecorder()

	cfg.handleVerify(w, ciRequest("application/json", cfg.guardCookie("lux", false)), authnPolicy)

	if w.Code != http.StatusNoContent {
		t.Fatalf("plain lux user on ci.hanzo.ai: status=%d want 204; body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Org-Id"); got != "lux" {
		t.Errorf("X-Org-Id=%q want lux — this header is the ONLY thing scoping the surface", got)
	}
	if got := w.Header().Get("X-Admin-Guard"); got != "allow-authn" {
		t.Errorf("X-Admin-Guard=%q want allow-authn", got)
	}
}

// TestAdminPolicyStillRefusesPlainOrgUser is the other half of the pair, and the
// regression guard for every surface already behind /__guard/verify: the exact
// principal the authn policy admits must still be refused by the admin policy on
// the same host. If this ever passes with 204, adding the authn policy silently
// opened platform.hanzo.ai, studio, commerce-admin and kms/admin.
func TestAdminPolicyStillRefusesPlainOrgUser(t *testing.T) {
	cfg := testConfig()
	w := httptest.NewRecorder()

	cfg.handleVerify(w, ciRequest("application/json", cfg.guardCookie("lux", false)), adminPolicy)

	if w.Code != http.StatusForbidden {
		t.Fatalf("plain lux user under adminPolicy: status=%d want 403 — the admin gate must be unchanged", w.Code)
	}
	if !strings.Contains(w.Body.String(), "admin access required") {
		t.Errorf("body=%q want the admin denial", w.Body.String())
	}
}

// TestAuthnPolicyStillRefusesAnonymous asserts the policy is AUTHN, not "open".
// Anonymous callers get the same treatment as on any other guarded surface: 401
// for an API client, an interactive IAM login for a browser.
func TestAuthnPolicyStillRefusesAnonymous(t *testing.T) {
	cfg := testConfig()

	t.Run("api → 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		cfg.handleVerify(w, ciRequest("application/json"), authnPolicy)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous API on authn surface: status=%d want 401", w.Code)
		}
		if got := w.Header().Get("X-Org-Id"); got != "" {
			t.Errorf("denied request wrote X-Org-Id=%q; must write nothing", got)
		}
	})

	t.Run("browser → 302 IAM login", func(t *testing.T) {
		w := httptest.NewRecorder()
		cfg.handleVerify(w, ciRequest("text/html"), authnPolicy)
		if w.Code != http.StatusFound {
			t.Fatalf("anonymous browser on authn surface: status=%d want 302", w.Code)
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://hanzo.id/v1/iam/oauth/authorize") {
			t.Errorf("Location=%q want the IAM PKCE login", loc)
		}
	})
}

// TestAuthnPolicyRefusesEmptyOwner covers the fail-closed case the policy exists
// to handle. A principal that resolved with no org would otherwise be passed
// through with a BLANK X-Org-Id, and a surface scoping by that header would then
// render every org's data to it. The predicate is asserted directly because a
// blank owner cannot be produced through the cookie path (guardCookie signs
// whatever it is given, but sessionPrincipal rejects a non-canonical payload).
func TestAuthnPolicyRefusesEmptyOwner(t *testing.T) {
	cfg := testConfig()
	for _, owner := range []string{"", "   ", "\t"} {
		if authnPolicy.allow(cfg, principal{owner: owner}, "ci.hanzo.ai") {
			t.Errorf("authnPolicy admitted owner=%q — a blank org must never scope a surface", owner)
		}
	}
	if !authnPolicy.allow(cfg, principal{owner: "zoo"}, "ci.hanzo.ai") {
		t.Error("authnPolicy refused a real org")
	}
}

// TestAuthnPolicyIgnoresHost pins the deliberate design choice: this policy
// grants REACH and never decides visibility, so it must not accidentally acquire
// host-dependent behavior. What a caller sees is decided downstream, by the
// X-Org-Id written from the verified owner claim.
func TestAuthnPolicyIgnoresHost(t *testing.T) {
	cfg := testConfig()
	p := principal{owner: "zoo"}
	for _, host := range []string{"ci.hanzo.ai", "admin.lux.cloud", "platform.hanzo.ai", "", "totally-unknown.example"} {
		if !authnPolicy.allow(cfg, p, host) {
			t.Errorf("authnPolicy denied on host=%q; it must be host-independent", host)
		}
	}
}

// TestPlatformSudoStillReachesAuthnSurface asserts the global admin is not
// accidentally excluded by the narrower policy — sudo carries a real owner
// (adminOrg), so it satisfies authn like any other identity.
func TestPlatformSudoStillReachesAuthnSurface(t *testing.T) {
	cfg := testConfig()
	w := httptest.NewRecorder()

	cfg.handleVerify(w, ciRequest("application/json", cfg.guardCookie("admin", true)), authnPolicy)

	if w.Code != http.StatusNoContent {
		t.Fatalf("platform sudo on authn surface: status=%d want 204", w.Code)
	}
	if got := w.Header().Get("X-Org-Id"); got != "admin" {
		t.Errorf("X-Org-Id=%q want admin", got)
	}
}

// TestAuthnAllowWritesIdentityTriple pins the header contract a gated surface
// resolves a PERSON from. X-Org-Id alone names the tenant, which every member of
// an org shares — a surface handed only that cannot tell two people apart and so
// cannot have users. o11y's iamidentn refuses outright when the subject is
// missing, so an org without a subject is not a partial assertion, it is an
// unusable one. All three headers, or the surface is still locked.
func TestAuthnAllowWritesIdentityTriple(t *testing.T) {
	cfg := testConfig()
	w := httptest.NewRecorder()

	cfg.handleVerify(w, ciRequest("application/json", cfg.guardCookie("lux", false)), authnPolicy)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d want 204; body=%s", w.Code, w.Body.String())
	}
	for header, want := range map[string]string{
		"X-Org-Id":     "lux",
		"X-User-Id":    "lux-uid",
		"X-User-Email": "lux@example.test",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s=%q want %q", header, got, want)
		}
	}
}

// TestSessionCookieCarriesTheWholePrincipal is the round-trip the browser
// actually takes: every request after the login reads the cookie, not the token.
// A cookie that carried only the tenant made the login the ONLY request that
// knew who you were, and the surface saw a bare org forever after.
func TestSessionCookieCarriesTheWholePrincipal(t *testing.T) {
	cfg := testConfig()
	want := principal{owner: "lux", isAdmin: false, uid: "0198f3c2-1111-7000-8000-000000000001", email: "z@lux.network"}

	w := httptest.NewRecorder()
	cfg.setSession(w, httptest.NewRequest(http.MethodGet, "https://ci.hanzo.ai/", nil), want)

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify-authn", nil)
	for _, ck := range w.Result().Cookies() {
		r.AddCookie(ck)
	}
	got, ok := cfg.sessionPrincipal(r)
	if !ok {
		t.Fatal("the cookie the guard just set did not parse back")
	}
	if got.owner != want.owner || got.uid != want.uid || got.email != want.email || got.isAdmin != want.isAdmin {
		t.Fatalf("round-trip lost fields: got %+v want %+v", got, want)
	}
}

// TestLegacySessionCookieRejected: the pre-v0.1.9 three-field payload is not a
// principal this build can render, so it fails closed and the holder logs in
// again. Accepting it would resurrect the exact half-identity the triple fixes.
func TestLegacySessionCookieRejected(t *testing.T) {
	cfg := testConfig()
	legacy := &http.Cookie{Name: cfg.cookieName, Value: cfg.sign("lux|0|" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))}

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify-authn", nil)
	r.AddCookie(legacy)
	if _, ok := cfg.sessionPrincipal(r); ok {
		t.Fatal("a three-field legacy cookie authenticated; it must fail closed")
	}
}

// TestCallbackPolicyRidesTheState is the lockout this release fixes. The OAuth
// callback is ONE path shared by every guarded surface, so it used to re-run the
// ADMIN predicate for all of them: a plain org user on an authn surface passed
// IAM, returned here, failed a test their surface never asked for, and was sent
// to the console with no session — so the next request restarted the same loop.
// The policy now rides the signed state, under the HMAC, where the browser
// cannot reach it; an unknown name still falls back to the stricter policy.
func TestCallbackPolicyRidesTheState(t *testing.T) {
	cfg := testConfig()

	w := httptest.NewRecorder()
	cfg.startLogin(w, ciRequest("text/html"), "https://ci.hanzo.ai/", authnPolicy)

	var state *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == stateCookie {
			state = ck
		}
	}
	if state == nil {
		t.Fatal("startLogin set no state cookie")
	}
	payload, ok := cfg.verifySigned(state.Value)
	if !ok {
		t.Fatal("state cookie failed its own signature check")
	}
	parts := strings.SplitN(payload, "\x1f", stateFields)
	if len(parts) != stateFields {
		t.Fatalf("state payload has %d fields, want %d", len(parts), stateFields)
	}
	if got := policyByName(parts[3]); got.name != authnPolicy.name {
		t.Fatalf("state carried policy %q, want %q — the callback would apply the wrong gate", got.name, authnPolicy.name)
	}
	if got := policyByName("something-this-build-never-wrote"); got.name != adminPolicy.name {
		t.Fatalf("unknown policy name resolved to %q, want the stricter %q", got.name, adminPolicy.name)
	}
}
