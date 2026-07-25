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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hanzoai/gateway/v2/iamauth"
)

// tenant_test.go proves the tenant-aware authorization boundary end-to-end
// through handleVerify (the real forward-auth entrypoint) on BOTH identity
// paths that carry a tenant admin: a Bearer JWT validated by the real iamauth
// validator, and a guard session cookie. The keystone invariant: a Lux tenant
// admin reaches ONLY admin.lux.* and is denied on every other brand's surface
// and on the global/DO-infra surfaces; the global platform-sudo org reaches
// everything.

const guardTestIssuer = "https://hanzo.id"

// guardSigner is a self-contained RSA signer + JWKS server so the tenant tests
// mint tokens the REAL iamauth validator accepts (issuer + audience + expiry +
// signature all enforced) — no shortcut around validation.
type guardSigner struct {
	key    *rsa.PrivateKey
	keyID  string
	signer gojose.Signer
}

func newGuardSigner(t *testing.T) *guardSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "admin-guard-test-key"
	opts := (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &guardSigner{key: key, keyID: kid, signer: signer}
}

func (gs *guardSigner) serveJWKS(t *testing.T) *httptest.Server {
	t.Helper()
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{
		Key:       &gs.key.PublicKey,
		KeyID:     gs.keyID,
		Algorithm: string(gojose.RS256),
		Use:       "sig",
	}}}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
}

// signPrincipal mints a valid JWT carrying the identity fields the guard trusts:
// owner (home org), isAdmin (home-org admin bit), and the org-membership set.
func (gs *guardSigner) signPrincipal(t *testing.T, owner string, isAdmin bool, orgs []iamauth.Membership) string {
	t.Helper()
	now := time.Now()
	claims := iamauth.Claims{
		Claims: jwt.Claims{
			Issuer:   guardTestIssuer,
			Subject:  owner + "/z",
			Audience: jwt.Audience{"hanzo-admin-guard"},
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		Owner:   owner,
		IsAdmin: isAdmin,
		Orgs:    orgs,
	}
	raw, err := jwt.Signed(gs.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// tenantTestConfig builds a guard whose JWT validator trusts gs's tokens (issuer
// hanzo.id, audience hanzo-admin-guard) via the test JWKS URL.
func tenantTestConfig(jwksURL string) *config {
	return &config{
		adminOrg:       "admin",
		consoles:       parseBrandMap(defaultConsoleMap),
		defaultConsole: "https://console.hanzo.ai",
		iamPublic:      "https://hanzo.id",
		clientID:       "hanzo-admin-guard",
		cookieName:     "hanzo_admin_guard",
		cookieTTL:      8 * time.Hour,
		hmacKey:        []byte("0123456789abcdef-tenant-test-key"),
		validator: iamauth.NewValidator(iamauth.Config{
			JWKSURL:   jwksURL,
			Issuer:    guardTestIssuer,
			Audiences: []string{"hanzo-admin-guard"},
			JWKSTTL:   time.Minute,
		}),
	}
}

// verdictBearer drives handleVerify as an API client presenting a Bearer JWT on
// host, returning the HTTP status (204 allow, 403 authenticated-but-denied, 401
// invalid/absent). API mode yields a clean status with no interactive redirect.
func verdictBearer(cfg *config, host, bearer string) int {
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", "/")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	cfg.handleVerify(w, r)
	return w.Code
}

// verdictCookie drives handleVerify as an API client (Accept: json → deterministic
// 204/403, no redirect) presenting a guard session cookie on host.
func verdictCookie(cfg *config, host string, cookie *http.Cookie) int {
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", "/")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	cfg.handleVerify(w, r)
	return w.Code
}

// TestTenantAdmin_LuxScopedToLuxSurface is the keystone: a Lux tenant admin
// (owner=lux, isAdmin=true) presented via a REAL validated Bearer JWT is allowed
// on Lux's own admin surfaces and DENIED everywhere else — the three required
// negatives plus the positives.
func TestTenantAdmin_LuxScopedToLuxSurface(t *testing.T) {
	gs := newGuardSigner(t)
	srv := gs.serveJWKS(t)
	defer srv.Close()
	cfg := tenantTestConfig(srv.URL)

	luxAdmin := gs.signPrincipal(t, "lux", true, nil)

	cases := []struct {
		host string
		want int
		why  string
	}{
		// Positive — Lux tenant admin on Lux surfaces.
		{"admin.lux.cloud", http.StatusNoContent, "lux admin on lux surface → allow"},
		{"admin.lux.network", http.StatusNoContent, "lux admin on lux's other domain → allow"},
		// Negative (a) — a foreign tenant surface.
		{"admin.zoo.cloud", http.StatusForbidden, "lux admin must NOT reach zoo surface"},
		// Negative (b) — the hanzo tenant surface.
		{"admin.hanzo.ai", http.StatusForbidden, "lux admin must NOT reach hanzo surface"},
		// Negative (c) — a global / DO-infra surface (not an admin.<brand> host).
		{"platform.hanzo.ai", http.StatusForbidden, "lux admin must NOT reach the global/DO-infra surface"},
		{"studio.hanzo.ai", http.StatusForbidden, "lux admin must NOT reach another global surface"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := verdictBearer(cfg, tc.host, luxAdmin); got != tc.want {
				t.Fatalf("%s: status=%d want %d (%s)", tc.host, got, tc.want, tc.why)
			}
		})
	}
}

// TestGlobalAdmin_AllSurfaces proves the global platform-sudo org (owner=admin)
// reaches EVERY admin surface — tenant, global, and even an unrecognized host —
// via the guard session cookie path.
func TestGlobalAdmin_AllSurfaces(t *testing.T) {
	cfg := tenantTestConfig("http://127.0.0.1:0") // validator unused on the cookie path
	globalAdmin := cfg.guardCookie("admin", true)

	for _, host := range []string{
		"admin.lux.cloud", "admin.zoo.cloud", "admin.hanzo.ai",
		"admin.pars.network", "platform.hanzo.ai", "admin.unknown.example",
	} {
		t.Run(host, func(t *testing.T) {
			if got := verdictCookie(cfg, host, globalAdmin); got != http.StatusNoContent {
				t.Fatalf("global admin on %s: status=%d want 204 (sudo reaches every surface)", host, got)
			}
		})
	}
}

// TestGlobalAdmin_AllSurfacesViaJWT mirrors the above on the Bearer JWT path, so
// the global grant is proven through the real validator too.
func TestGlobalAdmin_AllSurfacesViaJWT(t *testing.T) {
	gs := newGuardSigner(t)
	srv := gs.serveJWKS(t)
	defer srv.Close()
	cfg := tenantTestConfig(srv.URL)
	globalAdmin := gs.signPrincipal(t, "admin", true, nil)

	for _, host := range []string{"admin.lux.cloud", "admin.zoo.cloud", "platform.hanzo.ai", "admin.unknown.example"} {
		t.Run(host, func(t *testing.T) {
			if got := verdictBearer(cfg, host, globalAdmin); got != http.StatusNoContent {
				t.Fatalf("global admin (JWT) on %s: status=%d want 204", host, got)
			}
		})
	}
}

// TestTenantAdmin_LuxViaCookie proves the same tenant scoping on the guard
// session-cookie path (owner=lux, isAdmin=1).
func TestTenantAdmin_LuxViaCookie(t *testing.T) {
	cfg := tenantTestConfig("http://127.0.0.1:0")
	luxAdmin := cfg.guardCookie("lux", true)

	cases := map[string]int{
		"admin.lux.cloud":   http.StatusNoContent, // allow
		"admin.zoo.cloud":   http.StatusForbidden, // deny (foreign tenant)
		"admin.hanzo.ai":    http.StatusForbidden, // deny (foreign tenant)
		"platform.hanzo.ai": http.StatusForbidden, // deny (global surface)
	}
	for host, want := range cases {
		t.Run(host, func(t *testing.T) {
			if got := verdictCookie(cfg, host, luxAdmin); got != want {
				t.Fatalf("lux admin cookie on %s: status=%d want %d", host, got, want)
			}
		})
	}
}

// TestTenantMember_NotAdmin_Denied proves a plain member of the lux org (isAdmin
// false, no owner/admin membership) is NOT a lux tenant admin — denied even on
// lux's own surface. A tenant surface requires the ADMIN role, not membership.
func TestTenantMember_NotAdmin_Denied(t *testing.T) {
	gs := newGuardSigner(t)
	srv := gs.serveJWKS(t)
	defer srv.Close()
	cfg := tenantTestConfig(srv.URL)

	// (1) Home org lux, but only a member (isAdmin=false, role=member).
	luxMemberJWT := gs.signPrincipal(t, "lux", false, []iamauth.Membership{{Org: "lux", Role: "member"}})
	if got := verdictBearer(cfg, "admin.lux.cloud", luxMemberJWT); got != http.StatusForbidden {
		t.Fatalf("lux member (JWT) on admin.lux.cloud: status=%d want 403 (member is not a tenant admin)", got)
	}
	// (2) Same via cookie (owner=lux, isAdmin=0).
	if got := verdictCookie(cfg, "admin.lux.cloud", cfg.guardCookie("lux", false)); got != http.StatusForbidden {
		t.Fatalf("lux member cookie on admin.lux.cloud: status=%d want 403", got)
	}
}

// TestTenantAdmin_ViaMembershipSet proves the JWT path honors the org-membership
// set: a subject whose HOME org is unrelated but who holds an owner/admin role in
// lux via membership IS a lux tenant admin on lux surfaces — and still nothing
// else. This is the multi-org admin path the cookie path deliberately omits.
func TestTenantAdmin_ViaMembershipSet(t *testing.T) {
	gs := newGuardSigner(t)
	srv := gs.serveJWKS(t)
	defer srv.Close()
	cfg := tenantTestConfig(srv.URL)

	// Home org "acme" (non-admin there), but an ADMIN member of lux.
	crossOrgLuxAdmin := gs.signPrincipal(t, "acme", false, []iamauth.Membership{
		{Org: "lux", Role: "admin"},
		{Org: "zoo", Role: "member"},
	})
	if got := verdictBearer(cfg, "admin.lux.cloud", crossOrgLuxAdmin); got != http.StatusNoContent {
		t.Fatalf("cross-org lux admin on admin.lux.cloud: status=%d want 204 (admin via membership set)", got)
	}
	// Only a MEMBER of zoo → denied on the zoo surface.
	if got := verdictBearer(cfg, "admin.zoo.cloud", crossOrgLuxAdmin); got != http.StatusForbidden {
		t.Fatalf("zoo member on admin.zoo.cloud: status=%d want 403 (membership without admin role)", got)
	}
	// Not admin of hanzo at all → denied.
	if got := verdictBearer(cfg, "admin.hanzo.ai", crossOrgLuxAdmin); got != http.StatusForbidden {
		t.Fatalf("non-member on admin.hanzo.ai: status=%d want 403", got)
	}
}

// TestHostDeterminesTenant is the anti-spoof proof: authorization keys off the
// ingress-set X-Forwarded-Host, NOT the credential. The SAME lux admin cookie is
// allowed when the host is admin.lux.cloud and denied when the host is
// admin.zoo.cloud — so a stolen/replayed lux session cannot cross tenants by
// being replayed against another brand's host. (Deployment invariant: the
// ingress MUST set X-Forwarded-Host authoritatively and never pass a
// client-supplied one — see the guard's Red Handoff.)
func TestHostDeterminesTenant(t *testing.T) {
	cfg := tenantTestConfig("http://127.0.0.1:0")
	luxAdmin := cfg.guardCookie("lux", true)

	if got := verdictCookie(cfg, "admin.lux.cloud", luxAdmin); got != http.StatusNoContent {
		t.Fatalf("lux admin on admin.lux.cloud: status=%d want 204", got)
	}
	if got := verdictCookie(cfg, "admin.zoo.cloud", luxAdmin); got != http.StatusForbidden {
		t.Fatalf("SAME lux admin cookie on admin.zoo.cloud: status=%d want 403 (host, not cookie, decides the tenant)", got)
	}
}

// TestTenantOrgForHost is the exhaustive host→tenant-org derivation: only
// admin.<known-brand-domain> is a tenant surface; every global/unknown host
// fails closed.
func TestTenantOrgForHost(t *testing.T) {
	cases := []struct {
		host    string
		wantOrg string
		wantOK  bool
	}{
		{"admin.lux.cloud", "lux", true},
		{"admin.lux.network", "lux", true},
		{"admin.zoo.cloud", "zoo", true},
		{"admin.zoo.ngo", "zoo", true},
		{"admin.hanzo.ai", "hanzo", true},
		{"admin.hanzo.cloud", "hanzo", true},
		{"admin.pars.network", "pars", true},
		{"admin.bootno.de", "bootnode", true},
		{"admin.lux.cloud:443", "lux", true},   // port stripped
		{"ADMIN.LUX.CLOUD", "lux", true},       // case-insensitive
		{"platform.hanzo.ai", "", false},       // global surface, not admin.<brand>
		{"studio.hanzo.ai", "", false},         // global surface
		{"kms.hanzo.ai", "", false},            // global surface
		{"hanzo.ai", "", false},                // bare brand domain
		{"lux.cloud", "", false},               // bare brand domain
		{"admin.evil.com", "", false},          // unknown brand → fail closed
		{"admin.lux.evil.com", "", false},      // brand label but wrong registrable domain
		{"admin.notabrand.network", "", false}, // unknown → fail closed
		{"admin", "", false},                   // single label
		{"", "", false},                        // empty
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			gotOrg, gotOK := tenantOrgForHost(tc.host)
			if gotOrg != tc.wantOrg || gotOK != tc.wantOK {
				t.Fatalf("tenantOrgForHost(%q) = (%q,%v) want (%q,%v)", tc.host, gotOrg, gotOK, tc.wantOrg, tc.wantOK)
			}
		})
	}
}

// TestAuthorizeMatrix unit-tests the authorize predicate directly across the
// principal × host space, including the fail-closed corners (empty owner,
// unknown host admitting only sudo).
func TestAuthorizeMatrix(t *testing.T) {
	cfg := &config{adminOrg: "admin"}

	sudo := principal{owner: "admin", isAdmin: true}
	luxAdmin := principal{owner: "lux", isAdmin: true}
	luxMember := principal{owner: "lux", isAdmin: false}
	crossLuxAdmin := principal{owner: "acme", orgs: []iamauth.Membership{{Org: "lux", Role: "owner"}}}
	anon := principal{}

	cases := []struct {
		name string
		p    principal
		host string
		want bool
	}{
		{"sudo on tenant surface", sudo, "admin.lux.cloud", true},
		{"sudo on global surface", sudo, "platform.hanzo.ai", true},
		{"sudo on unknown host", sudo, "admin.evil.com", true},
		{"lux admin on lux", luxAdmin, "admin.lux.cloud", true},
		{"lux admin on zoo", luxAdmin, "admin.zoo.cloud", false},
		{"lux admin on hanzo", luxAdmin, "admin.hanzo.ai", false},
		{"lux admin on global", luxAdmin, "platform.hanzo.ai", false},
		{"lux member on lux", luxMember, "admin.lux.cloud", false},
		{"cross-org lux admin on lux", crossLuxAdmin, "admin.lux.cloud", true},
		{"cross-org lux admin on zoo", crossLuxAdmin, "admin.zoo.cloud", false},
		{"empty principal on tenant", anon, "admin.lux.cloud", false},
		{"empty principal on global", anon, "platform.hanzo.ai", false},
		{"empty principal owner not sudo", principal{owner: "", isAdmin: true}, "admin.lux.cloud", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.authorize(tc.p, tc.host); got != tc.want {
				t.Fatalf("authorize(%+v, %q) = %v want %v", tc.p, tc.host, got, tc.want)
			}
		})
	}
}
