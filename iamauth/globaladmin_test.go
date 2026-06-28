package iamauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
)

// TestClaims_GlobalAdmin is the core anti-conflation predicate: org-level
// IsAdmin (an org owner) is NOT a global admin; only the explicit
// isGlobalAdmin claim or membership in the admin org qualifies. This is the
// gateway-side mirror of commerce's TestIsGlobalAdmin.
func TestClaims_GlobalAdmin(t *testing.T) {
	cases := []struct {
		name     string
		claims   Claims
		adminOrg string
		want     bool
	}{
		{"admin org", Claims{Owner: "admin"}, "admin", true},
		{"admin org mixed-case", Claims{Owner: "Admin"}, "admin", true},
		{"admin org padded", Claims{Owner: " admin "}, "admin", true},
		{"explicit global flag, non-admin org", Claims{Owner: "hanzo", IsGlobalAdmin: true}, "admin", true},
		{"org-level isAdmin is NOT global (maxpower)", Claims{Owner: "maxpower", IsAdmin: true}, "admin", false},
		{"plain user", Claims{Owner: "hanzo"}, "admin", false},
		{"empty adminOrg never matches by owner", Claims{Owner: ""}, "", false},
		{"empty adminOrg + admin owner still no owner-match", Claims{Owner: "admin"}, "", false},
		{"custom admin org slug", Claims{Owner: "platform-admins"}, "platform-admins", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.claims.GlobalAdmin(tc.adminOrg); got != tc.want {
				t.Fatalf("GlobalAdmin(%q) on %+v = %v, want %v", tc.adminOrg, tc.claims, got, tc.want)
			}
		})
	}
}

func TestClaims_HasAudience(t *testing.T) {
	var c Claims
	c.Audience = jwt.Audience{"hanzo-admin-guard", "hanzo-app"}
	if !c.HasAudience("hanzo-admin-guard") {
		t.Fatal("expected HasAudience(hanzo-admin-guard)=true")
	}
	if c.HasAudience("hanzo-chat") {
		t.Fatal("token without hanzo-chat aud must not match it")
	}
	if c.HasAudience("") {
		t.Fatal("empty audience must never match")
	}
	var empty Claims
	if empty.HasAudience("hanzo-admin-guard") {
		t.Fatal("a token with no audiences must not match any")
	}
}

func TestAdminOrgFromEnv(t *testing.T) {
	t.Setenv("IAM_ADMIN_ORG", "")
	if got := AdminOrgFromEnv(); got != "admin" {
		t.Fatalf("default AdminOrg = %q, want admin", got)
	}
	t.Setenv("IAM_ADMIN_ORG", "platform-admins")
	if got := AdminOrgFromEnv(); got != "platform-admins" {
		t.Fatalf("AdminOrg override = %q, want platform-admins", got)
	}
}

// TestMintedHeaders_IncludeAndStripGlobalAdmin enforces the trust-boundary
// contract for the new platform signal: it is in the minted set AND stripped
// on ingress, so a client-forged X-User-IsGlobalAdmin can never survive to a
// downstream service.
func TestMintedHeaders_IncludeAndStripGlobalAdmin(t *testing.T) {
	found := false
	for _, h := range MintedIdentityHeaders {
		if h == "X-User-IsGlobalAdmin" {
			found = true
		}
	}
	if !found {
		t.Fatal("MintedIdentityHeaders must include X-User-IsGlobalAdmin")
	}
	r := httptest.NewRequest(http.MethodGet, "https://api.hanzo.ai/v1/x", nil)
	r.Header.Set("X-User-IsGlobalAdmin", "true") // forged by client
	StripIdentityHeaders(r)
	if v := r.Header.Get("X-User-IsGlobalAdmin"); v != "" {
		t.Fatalf("forged X-User-IsGlobalAdmin not stripped: %q", v)
	}
}

// TestInjectIdentity_GlobalAdminGating proves the gateway only emits the
// global signal for a real global admin, while still emitting the org-level
// signal for an org admin.
func TestInjectIdentity_GlobalAdminGating(t *testing.T) {
	// Global admin (admin org) → both signals.
	rGlobal := httptest.NewRequest(http.MethodGet, "/", nil)
	InjectIdentity(rGlobal, &Claims{Owner: "admin", IsAdmin: true}, "admin")
	if rGlobal.Header.Get("X-User-IsGlobalAdmin") != "true" {
		t.Fatal("global admin must get X-User-IsGlobalAdmin=true")
	}
	if rGlobal.Header.Get("X-User-IsAdmin") != "true" {
		t.Fatal("global admin still carries org-level X-User-IsAdmin")
	}

	// Org admin in a normal org → org signal only, NEVER global.
	rOrg := httptest.NewRequest(http.MethodGet, "/", nil)
	InjectIdentity(rOrg, &Claims{Owner: "maxpower", IsAdmin: true}, "admin")
	if rOrg.Header.Get("X-User-IsAdmin") != "true" {
		t.Fatal("org admin must keep X-User-IsAdmin")
	}
	if got := rOrg.Header.Get("X-User-IsGlobalAdmin"); got != "" {
		t.Fatalf("org admin must NOT get X-User-IsGlobalAdmin, got %q", got)
	}

	// Explicit isGlobalAdmin claim in a non-admin org → global signal.
	rFlag := httptest.NewRequest(http.MethodGet, "/", nil)
	InjectIdentity(rFlag, &Claims{Owner: "hanzo", IsGlobalAdmin: true}, "admin")
	if rFlag.Header.Get("X-User-IsGlobalAdmin") != "true" {
		t.Fatal("explicit isGlobalAdmin claim must emit X-User-IsGlobalAdmin")
	}
}
