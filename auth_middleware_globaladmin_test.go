package gateway

// Regression tests for the org-admin vs PLATFORM(global)-admin split.
//
// Bug (Red): the gateway minted only X-User-IsAdmin from the org-level
// `isAdmin` claim, and a downstream consumer (commerce admin_tenants) treated
// that as platform superadmin — so any org owner (e.g. maxpower) could perform
// cross-tenant superadmin ops. The gateway now mints a SEPARATE, spoof-proof
// X-User-IsGlobalAdmin ONLY for a real global admin (owner == AdminOrg, or the
// explicit isGlobalAdmin claim), while org admins keep X-User-IsAdmin for
// org-scoped RBAC.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// runGlobalAdminCase signs a token for the given owner/admin flags, runs it
// through the middleware (AdminOrg="admin"), and returns the identity headers
// observed downstream.
func runGlobalAdminCase(t *testing.T, owner string, isAdmin, isGlobalAdmin bool) (isAdminHdr, isGlobalHdr string) {
	t.Helper()
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, func(cfg *AuthConfig) {
		cfg.AdminOrg = "admin"
	})
	defer jwksServer.Close()

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.Owner = owner
	claims.IsAdmin = isAdmin
	claims.IsGlobalAdmin = isGlobalAdmin
	token := tj.signToken(t, claims)

	r.GET("/v1/x", func(c *gin.Context) {
		isAdminHdr = c.Request.Header.Get("X-User-IsAdmin")
		isGlobalHdr = c.Request.Header.Get("X-User-IsGlobalAdmin")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	return isAdminHdr, isGlobalHdr
}

func TestGateway_OrgAdminIsNotGlobalAdmin(t *testing.T) {
	// maxpower is an ORG owner: org-level isAdmin, NOT the admin org.
	isAdmin, isGlobal := runGlobalAdminCase(t, "maxpower", true, false)
	if isAdmin != "true" {
		t.Errorf("org admin must still get X-User-IsAdmin=true, got %q", isAdmin)
	}
	if isGlobal != "" {
		t.Errorf("SECURITY: org admin MUST NOT get X-User-IsGlobalAdmin, got %q", isGlobal)
	}
}

func TestGateway_GlobalAdminByAdminOrg(t *testing.T) {
	// A user in the admin org is a platform admin.
	isAdmin, isGlobal := runGlobalAdminCase(t, "admin", true, false)
	if isGlobal != "true" {
		t.Errorf("admin-org user must get X-User-IsGlobalAdmin=true, got %q", isGlobal)
	}
	if isAdmin != "true" {
		t.Errorf("admin-org user should also carry org-level X-User-IsAdmin, got %q", isAdmin)
	}
}

func TestGateway_GlobalAdminByExplicitClaim(t *testing.T) {
	// Explicit isGlobalAdmin claim, even in a non-admin org.
	_, isGlobal := runGlobalAdminCase(t, "hanzo", false, true)
	if isGlobal != "true" {
		t.Errorf("explicit isGlobalAdmin claim must get X-User-IsGlobalAdmin=true, got %q", isGlobal)
	}
}

func TestGateway_PlainUserGetsNeitherAdminSignal(t *testing.T) {
	isAdmin, isGlobal := runGlobalAdminCase(t, "hanzo", false, false)
	if isAdmin != "" || isGlobal != "" {
		t.Errorf("plain user must get no admin signals, got isAdmin=%q isGlobal=%q", isAdmin, isGlobal)
	}
}

// TestGateway_StripsForgedGlobalAdminHeader proves a client cannot smuggle the
// platform signal: even a plain user who hand-sets X-User-IsGlobalAdmin has it
// stripped before the validated identity is (not) minted.
func TestGateway_StripsForgedGlobalAdminHeader(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, func(cfg *AuthConfig) {
		cfg.AdminOrg = "admin"
	})
	defer jwksServer.Close()

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.Owner = "hanzo" // plain user, not global admin
	token := tj.signToken(t, claims)

	var gotGlobal string
	r.GET("/v1/x", func(c *gin.Context) {
		gotGlobal = c.Request.Header.Get("X-User-IsGlobalAdmin")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-IsGlobalAdmin", "true") // forged by client
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if gotGlobal != "" {
		t.Fatalf("SECURITY: forged X-User-IsGlobalAdmin reached backend: %q", gotGlobal)
	}
}
