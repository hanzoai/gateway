package main

// Audience-confinement tests for the admin-guard (Red item 2).
//
// Bug: the guard accepted ANY allowlisted audience, so a genuine IAM token
// minted for a DIFFERENT app (aud=hanzo-chat) — even a real global admin's —
// could be replayed against raw admin surfaces. The guard now requires the
// SPECIFIC admin audience (aud == adminAudience, by default the guard's own
// client_id) before the owner check; a wrong-audience token is rejected.
//
// Helpers here are uniquely named (audJWKS / audGuardConfig / signAud) so this
// file never collides with main_test.go or the concurrently-authored
// verify_test.go in the same package.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/hanzoai/gateway/v2/iamauth"
)

type audJWKS struct {
	key    *rsa.PrivateKey
	kid    string
	signer gojose.Signer
}

func newAudJWKS(t *testing.T) *audJWKS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	kid := "aud-test-key"
	sk := gojose.SigningKey{Algorithm: gojose.RS256, Key: key}
	signer, err := gojose.NewSigner(sk, (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return &audJWKS{key: key, kid: kid, signer: signer}
}

func (j *audJWKS) serve(t *testing.T) *httptest.Server {
	t.Helper()
	jwk := gojose.JSONWebKey{Key: &j.key.PublicKey, KeyID: j.kid, Algorithm: string(gojose.RS256), Use: "sig"}
	data, err := json.Marshal(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
}

func (j *audJWKS) signAud(t *testing.T, owner, audience string) string {
	t.Helper()
	now := time.Now()
	claims := iamauth.Claims{
		Claims: jwt.Claims{
			Issuer:   "https://hanzo.id",
			Subject:  "z",
			Audience: jwt.Audience{audience},
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		Owner: owner,
	}
	raw, err := jwt.Signed(j.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// audGuardConfig builds a guard config whose validator trusts jwksURL and whose
// allowlist is broad (incl. a non-admin aud) so the audience GATE — not the
// generic validator — is what rejects a wrong-audience token. iamInternal is a
// closed address so identity-source (3) fails fast in browser fall-through.
func audGuardConfig(jwksURL, adminAud string) *config {
	vcfg := iamauth.Config{
		JWKSURL:   jwksURL,
		Issuer:    "https://hanzo.id",
		Audiences: []string{"hanzo-chat", adminAud}, // broad: includes a non-admin aud
		JWKSTTL:   time.Minute,
		AdminOrg:  "admin",
	}
	return &config{
		adminOrg:      "admin",
		adminAudience: adminAud,
		consoleURL:    "https://console.hanzo.ai",
		iamPublic:     "https://hanzo.id",
		iamInternal:   "http://127.0.0.1:1", // refused → get-account source fails fast
		clientID:      adminAud,
		cookieName:    "hanzo_admin_guard",
		cookieDomain:  ".hanzo.ai",
		cookieTTL:     time.Hour,
		hmacKey:       []byte("0123456789abcdef-aud-confinement-test"),
		validator:     iamauth.NewValidator(vcfg),
	}
}

func newGuardVerifyReq(bearer, accept string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "platform.hanzo.ai")
	r.Header.Set("X-Forwarded-Uri", "/admin")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

// TestAudienceConfinement_AdminAudience proves the matrix on the API (Bearer)
// path: a token minted for the admin-guard with a global-admin owner is the
// ONLY one allowed; the same audience for a non-global owner is 403'd by the
// owner check, and a global admin's token for ANOTHER app is 403'd by the
// audience gate.
func TestAudienceConfinement_AdminAudience(t *testing.T) {
	j := newAudJWKS(t)
	jwks := j.serve(t)
	defer jwks.Close()
	cfg := audGuardConfig(jwks.URL, "hanzo-admin-guard")

	cases := []struct {
		name       string
		owner      string
		audience   string
		wantStatus int
		wantBody   string
	}{
		{"admin-aud + global admin → 204", "admin", "hanzo-admin-guard", http.StatusNoContent, ""},
		{"admin-aud + org-owner (non-global) → 403", "maxpower", "hanzo-admin-guard", http.StatusForbidden, "global admin required"},
		{"WRONG-aud + global admin → 403 (audience confinement)", "admin", "hanzo-chat", http.StatusForbidden, "token audience not authorized"},
		{"WRONG-aud + org-owner → 403", "maxpower", "hanzo-chat", http.StatusForbidden, "token audience not authorized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := j.signAud(t, tc.owner, tc.audience)
			r := newGuardVerifyReq(tok, "application/json", nil)
			w := httptest.NewRecorder()
			cfg.handleVerify(w, r)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d (body=%s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus == http.StatusNoContent {
				if w.Header().Get("X-Admin-Guard") != "allow" {
					t.Errorf("allow path must set X-Admin-Guard=allow")
				}
				if w.Header().Get("X-Org-Id") != "admin" {
					t.Errorf("allow path X-Org-Id=%q want admin", w.Header().Get("X-Org-Id"))
				}
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Errorf("body=%q want substring %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestAudienceConfinement_WrongAudienceBrowserFallsThrough proves a browser
// (html Accept, no Bearer) presenting a wrong-audience cookie token is NOT
// hard-403'd; it falls through to the interactive IAM login (302), preserving
// the content-negotiation contract.
func TestAudienceConfinement_WrongAudienceBrowserFallsThrough(t *testing.T) {
	j := newAudJWKS(t)
	jwks := j.serve(t)
	defer jwks.Close()
	cfg := audGuardConfig(jwks.URL, "hanzo-admin-guard")

	// Wrong-audience token delivered as a session cookie (browser), no Bearer.
	tok := j.signAud(t, "admin", "hanzo-chat")
	r := newGuardVerifyReq("", "text/html", &http.Cookie{Name: "iam_access_token", Value: tok})
	w := httptest.NewRecorder()
	cfg.handleVerify(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("browser wrong-aud: status=%d want 302 (fall through to login); body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://hanzo.id/v1/iam/oauth/authorize") {
		t.Fatalf("browser wrong-aud: Location=%q want IAM authorize", loc)
	}
}

// TestAppendAudience guards the small allowlist helper.
func TestAppendAudience(t *testing.T) {
	got := appendAudience([]string{"a", "b"}, "b")
	if len(got) != 2 {
		t.Fatalf("duplicate aud should not be appended: %v", got)
	}
	got = appendAudience([]string{"a"}, "c")
	if fmt.Sprint(got) != "[a c]" {
		t.Fatalf("append new aud: %v", got)
	}
	got = appendAudience([]string{"a"}, "")
	if len(got) != 1 {
		t.Fatalf("empty aud must be a no-op: %v", got)
	}
}
