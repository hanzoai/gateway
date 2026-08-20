// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// gin-driven: this suite drives the LEGACY Lura edge's transports
// (legacy_transports.go), which exist only under this tag. The policies it
// exercises are framework-free values shared with the zip edge, and
// transport_parity_test.go asserts the two edges answer alike.

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// These tests pin the CTO's orthogonal-route-class design for the tokenless
// Sentry/o11y DSN ingest edge:
//   - Class 1 (ingest): POST .../{envelope,store}[/] forwards to cloud with NO
//     IAM-JWT gate and NO written/forwarded identity (cloud DSN-auths + org-from-DSN).
//   - Class 2 (authed): every other /v1/* validates the IAM-JWT and WRITES identity
//     FROM the JWT over a stripped slate — the gateway is the SOLE identity source.
// The global ingress strip is load-bearing (several identity headers are written only
// conditionally, so a forged copy would otherwise survive on the authed class).

type backendSaw struct {
	reached bool
	org     string
	user    string
	glob    string // X-User-IsGlobalAdmin
	owner   string // X-User-Owner (home org)
}

func recordingBackend(r *gin.Engine, saw *backendSaw) {
	r.Any("/*path", func(c *gin.Context) {
		saw.reached = true
		saw.org = c.Request.Header.Get("X-Org-Id")
		saw.user = c.Request.Header.Get("X-User-Id")
		saw.glob = c.Request.Header.Get("X-User-IsGlobalAdmin")
		saw.owner = c.Request.Header.Get("X-User-Owner")
		c.Status(http.StatusOK)
	})
}

func send(r *gin.Engine, method, path, auth string, forged map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = "api.hanzo.ai"
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for k, v := range forged {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Scenarios 1, 2, 6: an authed Sentry READ with no JWT (with or without a forged
// X-Org-Id) is 401 — the read routes to the AUTHED class, never the ingest class.
func TestIngestClass_AuthedReadRequiresJWT(t *testing.T) {
	r, _, jwks := setupMiddlewareWithJWKS(t, nil)
	defer jwks.Close()
	var saw backendSaw
	recordingBackend(r, &saw)

	if w := send(r, http.MethodGet, "/v1/sentinel/issues?project=019f5339", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("read with no JWT: got %d, want 401", w.Code)
	}
	// A forged X-Org-Id must NOT buy a read (the gate rejects for lack of a valid JWT).
	if w := send(r, http.MethodGet, "/v1/sentinel/issues", "", map[string]string{"X-Org-Id": "victim-org"}); w.Code != http.StatusUnauthorized {
		t.Errorf("read with forged X-Org-Id + no JWT: got %d, want 401", w.Code)
	}
	if saw.reached {
		t.Error("SECURITY: an unauthenticated read reached the backend")
	}
}

// Scenario 3 (+ the load-bearing-strip proof): a valid JWT with a forged X-Org-Id
// AND a forged X-User-IsGlobalAdmin — the backend must see the JWT's org (hanzo),
// NOT the forged org, and must NOT see global-admin (the JWT asserts neither, and
// the conditional write does not re-set it, so the strip is what defeats the forge).
func TestIngestClass_AuthedWriteOverwritesForgedIdentity(t *testing.T) {
	r, tj, jwks := setupMiddlewareWithJWKS(t, nil)
	defer jwks.Close()
	var saw backendSaw
	recordingBackend(r, &saw)

	tok := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai")) // Owner=hanzo, not global-admin
	w := send(r, http.MethodGet, "/v1/sentinel/issues", tok, map[string]string{
		"X-Org-Id":             "victim-org",
		"X-User-IsGlobalAdmin": "true",
		"X-User-Owner":         "admin",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("valid-JWT read: got %d, want 200", w.Code)
	}
	if !saw.reached {
		t.Fatal("valid-JWT read did not reach the backend")
	}
	if saw.org != "hanzo" {
		t.Errorf("SECURITY: backend saw X-Org-Id %q, want the JWT owner \"hanzo\" (forge not overwritten)", saw.org)
	}
	if saw.owner != "hanzo" {
		t.Errorf("SECURITY: backend saw X-User-Owner %q, want JWT owner \"hanzo\" (home org from JWT; forged \"admin\" overwritten)", saw.owner)
	}
	if saw.glob != "" {
		t.Errorf("SECURITY: forged legacy X-User-IsGlobalAdmin survived (%q) — never written now (platform sudo = org==admin); the ingress strip must drop a forged copy", saw.glob)
	}
}

// Scenario 4: tokenless DSN ingest through the gateway reaches cloud (not 401).
func TestIngestClass_TokenlessIngestReachesBackend(t *testing.T) {
	r, _, jwks := setupMiddlewareWithJWKS(t, nil)
	defer jwks.Close()
	var saw backendSaw
	recordingBackend(r, &saw)

	for _, p := range []string{
		"/v1/event/019f5339/envelope/",
		"/v1/event/019f5339/store/",
		"/v1/o11y/api/hanzo/envelope/", // the o11y errortracking wire, same class
	} {
		saw = backendSaw{}
		w := send(r, http.MethodPost, p, "", nil)
		if w.Code == http.StatusUnauthorized {
			t.Errorf("tokenless ingest %s was 401; must pass through to DSN auth at cloud", p)
		}
		if !saw.reached {
			t.Errorf("tokenless ingest %s did not reach the backend", p)
		}
	}
}

// Scenario 5: the ingest class forwards NO client identity — a forged X-Org-Id on
// an ingest POST is stripped, so cloud only ever has the DSN to resolve the org.
func TestIngestClass_IngestForwardsNoClientIdentity(t *testing.T) {
	r, _, jwks := setupMiddlewareWithJWKS(t, nil)
	defer jwks.Close()
	var saw backendSaw
	recordingBackend(r, &saw)

	w := send(r, http.MethodPost, "/v1/event/019f5339/envelope/", "", map[string]string{
		"X-Org-Id":             "victim-org",
		"X-User-Id":            "attacker",
		"X-User-IsGlobalAdmin": "true",
		"X-User-Owner":         "admin",
	})
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("tokenless ingest was 401; must pass through")
	}
	if saw.org != "" || saw.user != "" || saw.glob != "" || saw.owner != "" {
		t.Errorf("SECURITY: ingest forwarded client identity (org=%q user=%q glob=%q owner=%q); it must forward none — cloud resolves org from the DSN", saw.org, saw.user, saw.glob, saw.owner)
	}
}
