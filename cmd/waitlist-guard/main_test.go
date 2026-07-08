// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hanzoai/gateway/v2/iamauth"
)

// newTestConfig builds a guard config pointed at a fake IAM, with a real (but
// unreachable-JWKS) validator so an unauthenticated request cleanly returns
// ErrNoToken and falls through to the IAM-session path under test.
func newTestConfig(iamURL string, failOpen bool) *config {
	return &config{
		iamPublic:    iamURL,
		iamInternal:  iamURL,
		adminOrg:     "admin",
		failOpen:     failOpen,
		waitlistURL:  "https://waitlist.hanzo.ai",
		cookieDomain: ".hanzo.ai",
		cookieName:   "hanzo_waitlist_guard",
		cookieTTL:    8 * time.Hour,
		hmacKey:      []byte("0123456789abcdef0123456789abcdef"),
		validator:    iamauth.NewValidator(iamauth.Config{Issuer: "https://iam.hanzo.ai"}),
	}
}

// browserReq is a browser-style forward-auth request (Accept: text/html) with an
// IAM session cookie but NO guard cookie and NO bearer — so handleVerify reaches
// the IAM get-account (path 3).
func browserReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-Host", "console.hanzo.ai")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Uri", "/")
	r.Header.Set("Cookie", "casdoor_session_id=abc")
	return r
}

// TestPath3NeverFailsOpen (Red R-4): path 3 resolves identity from a RAW inbound
// cookie the guard has NOT validated. During an IAM outage (5xx) it must NEVER
// fail open — an anonymous caller with a junk cookie would otherwise ride through.
// Every IAM outcome × failOpen setting on a mere-cookie request → interactive
// login (302), never 204 allow.
func TestPath3NeverFailsOpen(t *testing.T) {
	for _, iamStatus := range []int{500, 503, 404} {
		for _, failOpen := range []bool{true, false} {
			iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(iamStatus)
			}))
			c := newTestConfig(iam.URL, failOpen)
			rec := httptest.NewRecorder()
			c.handleVerify(rec, browserReq())
			iam.Close()
			if rec.Code == http.StatusNoContent || rec.Header().Get("X-Waitlist-Guard") == "allow" {
				t.Fatalf("path-3 (unvalidated cookie) failed OPEN: iamStatus=%d failOpen=%v code=%d",
					iamStatus, failOpen, rec.Code)
			}
			if rec.Code != http.StatusFound {
				t.Fatalf("path-3 iamStatus=%d failOpen=%v: code=%d want 302 login", iamStatus, failOpen, rec.Code)
			}
		}
	}
}

// jwtReq mints an RSA-signed JWT (owner=hanzo, name=alice, non-admin, aud in the
// validator allowlist) and returns a forward-auth request bearing it — so
// handleVerify reaches path 2 (validated JWT) with a live get-user lookup.
func jwtSignerConfig(t *testing.T, iamURL string, failOpen bool) (*config, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid, iss, aud = "wg-test-key", "https://iam.hanzo.ai", "hanzo-waitlist-guard"
	opts := (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	jwks, _ := json.Marshal(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{
		Key: &key.PublicKey, KeyID: kid, Algorithm: string(gojose.RS256), Use: "sig",
	}}})
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(jwksSrv.Close)

	now := time.Now()
	claims := iamauth.Claims{Claims: jwt.Claims{
		Issuer: iss, Subject: "alice", Audience: jwt.Audience{aud},
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}, Owner: "hanzo", Name: "alice"}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	c := newTestConfig(iamURL, failOpen)
	c.validator = iamauth.NewValidator(iamauth.Config{
		JWKSURL: jwksSrv.URL, Issuer: iss, Audiences: []string{aud}, JWKSTTL: time.Minute,
	})
	return c, raw
}

// TestPath2FailOpenOnIAM5xx (Red R-4 counterpart): a VALIDATED JWT is the ONLY
// signal permitted to fail open. get-user 5xx + failOpen ⇒ allow; 5xx + fail-closed
// ⇒ deny; a 4xx (definitive) or a live "pending" ⇒ deny regardless; live "approved"
// ⇒ allow. API client (Bearer) unapproved ⇒ 403, approved ⇒ 204.
func TestPath2FailOpenOnIAM5xx(t *testing.T) {
	cases := []struct {
		name       string
		getUser    func(w http.ResponseWriter)
		failOpen   bool
		wantStatus int
	}{
		{"5xx + fail-open ⇒ allow", func(w http.ResponseWriter) { w.WriteHeader(500) }, true, http.StatusNoContent},
		{"5xx + fail-closed ⇒ 403", func(w http.ResponseWriter) { w.WriteHeader(503) }, false, http.StatusForbidden},
		{"4xx never fails open ⇒ 403", func(w http.ResponseWriter) { w.WriteHeader(404) }, true, http.StatusForbidden},
		{"live pending ⇒ 403", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"owner":"hanzo","name":"alice","properties":{"approvalStatus":"pending"}}`))
		}, true, http.StatusForbidden},
		{"live approved ⇒ 204", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"owner":"hanzo","name":"alice","properties":{"approvalStatus":"approved"}}`))
		}, true, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.getUser(w) }))
			defer iam.Close()
			c, token := jwtSignerConfig(t, iam.URL, tc.failOpen)
			r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
			r.Header.Set("X-Forwarded-Host", "console.hanzo.ai")
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			c.handleVerify(rec, r)
			if rec.Code != tc.wantStatus {
				t.Fatalf("code=%d want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestFailOpenApprovedFromIAM200: when IAM is UP, the real approval decides —
// a pending user is bounced to the waitlist, an approved user is allowed.
func TestApprovalFromLiveIAM(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"pending ⇒ waitlist", `{"owner":"hanzo","name":"u","properties":{"approvalStatus":"pending"}}`, http.StatusFound},
		{"approved ⇒ allow", `{"owner":"hanzo","name":"u","properties":{"approvalStatus":"approved"}}`, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer iam.Close()
			c := newTestConfig(iam.URL, true)
			rec := httptest.NewRecorder()
			c.handleVerify(rec, browserReq())
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusFound && rec.Header().Get("Location") != c.waitlistURL {
				t.Fatalf("unapproved not sent to waitlist: Location=%q", rec.Header().Get("Location"))
			}
		})
	}
}

// TestStripsInboundIdentityHeaders: a client that forges X-Org-Id / X-Waitlist-*
// must not have them survive into the guard's request view. The guard strips them
// up front (defense in depth), so its own logic never reads a forged value.
func TestStripsInboundIdentityHeaders(t *testing.T) {
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // force fail-open path, irrelevant to the assertion
	}))
	defer iam.Close()
	c := newTestConfig(iam.URL, true)
	r := browserReq()
	r.Header.Set("X-Org-Id", "admin")
	r.Header.Set("X-Waitlist-Guard", "allow")
	r.Header.Set("X-Waitlist-Approved", "1")
	c.handleVerify(httptest.NewRecorder(), r)
	for _, h := range []string{"X-Org-Id", "X-Waitlist-Guard", "X-Waitlist-Approved"} {
		if v := r.Header.Get(h); v != "" {
			t.Fatalf("forged inbound %s survived stripping: %q", h, v)
		}
	}
}

// TestHostAllowed locks the X-Forwarded-Host trust rule: same-suffix hosts pass,
// foreign hosts are rejected (so a spoofed forwarded host can't steer redirect_uri).
func TestHostAllowed(t *testing.T) {
	suffix := &config{cookieDomain: ".hanzo.ai"}
	if !suffix.hostAllowed("console.hanzo.ai") || !suffix.hostAllowed("hanzo.ai") {
		t.Fatal("same-suffix host rejected")
	}
	if suffix.hostAllowed("evil.com") || suffix.hostAllowed("hanzo.ai.evil.com") {
		t.Fatal("foreign host accepted")
	}
	explicit := &config{cookieDomain: ".hanzo.ai", allowedHosts: map[string]bool{"console.hanzo.ai": true}}
	if !explicit.hostAllowed("console.hanzo.ai") || explicit.hostAllowed("app.hanzo.ai") {
		t.Fatal("explicit allowlist not enforced")
	}
}

// TestSafeHostRejectsSpoof: a spoofed X-Forwarded-Host falls back to r.Host.
func TestSafeHostRejectsSpoof(t *testing.T) {
	c := &config{cookieDomain: ".hanzo.ai"}
	r := httptest.NewRequest(http.MethodGet, "https://console.hanzo.ai/__guard/verify", nil)
	r.Host = "console.hanzo.ai"
	r.Header.Set("X-Forwarded-Host", "evil.com")
	if got := c.safeHost(r); got != "console.hanzo.ai" {
		t.Fatalf("safeHost honored a spoofed forwarded host: %q", got)
	}
}

// TestStartLoginHasNoOrgPin: the waitlist-guard must NOT pin organization=admin
// (that admin-guard inheritance would break consumer login).
func TestStartLoginHasNoOrgPin(t *testing.T) {
	c := newTestConfig("https://hanzo.id", true)
	c.clientID = "hanzo-waitlist-guard"
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Host = "console.hanzo.ai"
	r.Header.Set("X-Forwarded-Host", "console.hanzo.ai")
	r.Header.Set("X-Forwarded-Proto", "https")
	c.startLogin(rec, r, "https://console.hanzo.ai/")
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad authorize URL: %v", err)
	}
	if u.Query().Has("organization") {
		t.Fatalf("authorize URL still pins organization=%q — consumer login would break", u.Query().Get("organization"))
	}
}

// TestApprovalFromAccount locks the gate's core predicate. It MUST fail-OPEN for
// existing users (no property ⇒ approved), gate only an explicit "pending", treat
// admins (owner==adminOrg or isAdmin) as always approved, parse both the top-level
// and data-wrapped IAM shapes, and reject an error/ownerless body.
func TestApprovalFromAccount(t *testing.T) {
	const adminOrg = "admin"
	cases := []struct {
		name         string
		body         string
		wantOwner    string
		wantApproved bool
		wantOK       bool
	}{
		{"error body", `{"status":"error","msg":"nope"}`, "", false, false},
		{"empty owner", `{"status":"ok"}`, "", false, false},
		{"existing user no props -> approved (fail-open)", `{"owner":"hanzo","name":"a"}`, "hanzo", true, true},
		{"explicit approved", `{"owner":"hanzo","properties":{"approvalStatus":"approved"}}`, "hanzo", true, true},
		{"explicit pending -> gated", `{"owner":"hanzo","properties":{"approvalStatus":"pending"}}`, "hanzo", false, true},
		{"rejected (not pending) -> approved-by-fallthrough", `{"owner":"hanzo","properties":{"approvalStatus":"rejected"}}`, "hanzo", true, true},
		{"pending but global admin -> approved", `{"owner":"admin","properties":{"approvalStatus":"pending"}}`, "admin", true, true},
		{"pending but isAdmin -> approved", `{"owner":"hanzo","isAdmin":true,"properties":{"approvalStatus":"pending"}}`, "hanzo", true, true},
		{"data-wrapped pending", `{"status":"ok","data":{"owner":"hanzo","properties":{"approvalStatus":"pending"}}}`, "hanzo", false, true},
		{"data-wrapped existing -> approved", `{"status":"ok","data":{"owner":"zoo","name":"b"}}`, "zoo", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, approved, ok := approvalFromAccount([]byte(tc.body), adminOrg)
			if owner != tc.wantOwner || approved != tc.wantApproved || ok != tc.wantOK {
				t.Fatalf("approvalFromAccount(%s) = (%q,%v,%v); want (%q,%v,%v)",
					tc.body, owner, approved, ok, tc.wantOwner, tc.wantApproved, tc.wantOK)
			}
		})
	}
}

// TestSessionForgeryRejected verifies the signed session cookie is tamper-evident:
// an attacker who flips the approved bit (0→1) in the cleartext half while keeping
// the original MAC is REJECTED. The gate must never trust a forged approved bit.
func TestSessionForgeryRejected(t *testing.T) {
	c := &config{hmacKey: []byte("0123456789abcdef0123456789abcdef")}

	// Legit unapproved session, signed correctly.
	unapproved := "hanzo|0|9999999999"
	signed := c.sign(unapproved)
	if got, ok := c.verifySigned(signed); !ok || got != unapproved {
		t.Fatalf("round-trip failed: ok=%v got=%q", ok, got)
	}

	// Attacker rewrites ONLY the base64(payload) half to say approved=1, reusing
	// the original MAC (base64(mac)). verifySigned must reject it.
	_, macB64, _ := strings.Cut(signed, ".")
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte("hanzo|1|9999999999"))
	forged := forgedPayload + "." + macB64
	if _, ok := c.verifySigned(forged); ok {
		t.Fatal("verifySigned ACCEPTED a forged approved bit — the gate is bypassable")
	}
}

// TestStripMiddlewareCoversAuthoritativeSet is the DRY guard: the generated
// ingress `waitlist-strip` MUST enumerate every exact header the gateway strips
// (iamauth.StripIdentityHeaderNames) plus the guard's own minted headers, so the
// ingress config fronting a direct-to-backend route can never silently drift and
// leave a forgeable identity header (Red H-2).
func TestStripMiddlewareCoversAuthoritativeSet(t *testing.T) {
	var buf bytes.Buffer
	printStripMiddleware(&buf)
	out := buf.String()
	for _, h := range append(append([]string{}, iamauth.StripIdentityHeaderNames...), waitlistMintedHeaders...) {
		if !strings.Contains(out, h+`: ""`) {
			t.Fatalf("generated waitlist-strip is MISSING %q — ingress strip would drift from the guard", h)
		}
	}
	// Brand-neutral end state: the generated strip must NOT contain any vendor
	// prefix — it is exact-name only, covering the full set with no wildcard gap.
	if strings.Contains(strings.ToUpper(out), "X-IAM-") || strings.Contains(strings.ToUpper(out), "X-HANZO-") {
		t.Fatal("generated strip still contains a vendor-prefixed header — not brand-neutral")
	}
}

// TestSessionBoundToUser: a valid 4-part session round-trips; a legacy 3-part
// payload (pre-binding) is rejected (forwards-only, no silent downgrade).
func TestSessionBoundToUser(t *testing.T) {
	c := newTestConfig("https://iam.hanzo.ai", true)
	rec := httptest.NewRecorder()
	c.setSession(rec, "maxpower", "dave", true)
	ck := rec.Result().Cookies()[0]
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.AddCookie(ck)
	owner, approved, ok := c.sessionOwner(r)
	if !ok || owner != "maxpower" || !approved {
		t.Fatalf("round-trip failed: owner=%q approved=%v ok=%v", owner, approved, ok)
	}
	// A legacy 3-part payload must not parse.
	r2 := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r2.AddCookie(&http.Cookie{Name: c.cookieName, Value: c.sign("maxpower|1|9999999999")})
	if _, _, ok := c.sessionOwner(r2); ok {
		t.Fatal("legacy 3-part session accepted — binding not enforced")
	}
}
