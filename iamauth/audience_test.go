package iamauth

// Bug A regression: IAM stamps user tokens with aud=<client_id>
// (e.g. hanzo-app, hanzo-chat), never the gateway origin. A single fixed
// expected audience therefore rejected EVERY normal user JWT (cowork AI 401,
// user billing 401). ValidateToken now matches the token audience against an
// allowlist (OR semantics). These tests pin that contract: known client_ids
// pass, an unknown audience fails, and issuer validation stays strict.

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
)

// testSigner is a self-contained RSA signer + JWKS server for edge-auth tests.
type testSigner struct {
	key    *rsa.PrivateKey
	keyID  string
	signer gojose.Signer
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid := "iamauth-test-key"
	opts := (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &testSigner{key: key, keyID: kid, signer: signer}
}

// serveJWKS starts an httptest server publishing the public key. Caller defers Close.
func (ts *testSigner) serveJWKS(t *testing.T) *httptest.Server {
	t.Helper()
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{
		Key:       &ts.key.PublicKey,
		KeyID:     ts.keyID,
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

// sign mints a JWT with the given issuer and audience.
func (ts *testSigner) sign(t *testing.T, issuer, audience string) string {
	t.Helper()
	now := time.Now()
	claims := Claims{Claims: jwt.Claims{
		Issuer:   issuer,
		Subject:  "alice",
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}, Owner: "hanzo", Email: "alice@hanzo.ai"}
	raw, err := jwt.Signed(ts.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

const testIssuer = "https://iam.hanzo.ai"

// TestValidateToken_AudienceAllowlist is the Bug A keystone: user tokens whose
// aud is a known client_id pass; an unknown audience fails; a wrong issuer
// fails even with an accepted audience.
func TestValidateToken_AudienceAllowlist(t *testing.T) {
	ts := newTestSigner(t)
	srv := ts.serveJWKS(t)
	defer srv.Close()
	cache := NewJWKSCache(srv.URL, time.Minute)

	allow := []string{"hanzo-app", "hanzo-console", "hanzo-chat", "hanzo-id", "https://api.hanzo.ai"}

	cases := []struct {
		name      string
		issuer    string
		audience  string
		wantValid bool
	}{
		{"client_id hanzo-app passes", testIssuer, "hanzo-app", true},
		{"client_id hanzo-chat passes", testIssuer, "hanzo-chat", true},
		{"client_id hanzo-console passes", testIssuer, "hanzo-console", true},
		{"gateway origin passes", testIssuer, "https://api.hanzo.ai", true},
		{"unknown audience fails", testIssuer, "evil", false},
		{"unknown audience (other origin) fails", testIssuer, "https://evil.example", false},
		{"wrong issuer fails (audience ok)", "https://evil-issuer.example", "hanzo-app", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := ts.sign(t, tc.issuer, tc.audience)
			claims, err := ValidateToken(tok, cache, testIssuer, allow)
			if tc.wantValid {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				if claims == nil || claims.UserID() != "alice" {
					t.Fatalf("expected claims for alice, got %+v", claims)
				}
			} else if err == nil {
				t.Fatalf("expected rejection for issuer=%q aud=%q, got valid", tc.issuer, tc.audience)
			}
		})
	}
}

// TestValidateToken_MissingIssuerRejected guards the existing invariant: a
// token with no issuer claim is rejected even when its audience is allowed.
func TestValidateToken_MissingIssuerRejected(t *testing.T) {
	ts := newTestSigner(t)
	srv := ts.serveJWKS(t)
	defer srv.Close()
	cache := NewJWKSCache(srv.URL, time.Minute)

	tok := ts.sign(t, "", "hanzo-app")
	if _, err := ValidateToken(tok, cache, testIssuer, []string{"hanzo-app"}); err == nil {
		t.Fatal("token with empty issuer must be rejected")
	}
}

func TestAudiencesFromEnv(t *testing.T) {
	t.Run("baked default includes client_ids and origin", func(t *testing.T) {
		t.Setenv("GATEWAY_ALLOWED_AUDIENCES", "")
		t.Setenv("AUTH_AUDIENCE", "")
		got := AudiencesFromEnv()
		for _, want := range []string{"hanzo-app", "hanzo-chat", "https://api.hanzo.ai"} {
			if !contains(got, want) {
				t.Errorf("default %v missing %q", got, want)
			}
		}
	})

	t.Run("GATEWAY_ALLOWED_AUDIENCES fully overrides", func(t *testing.T) {
		t.Setenv("GATEWAY_ALLOWED_AUDIENCES", "a, b ,c")
		got := AudiencesFromEnv()
		if len(got) != 3 || !contains(got, "a") || !contains(got, "b") || !contains(got, "c") {
			t.Fatalf("override list = %v, want [a b c]", got)
		}
		if contains(got, "hanzo-app") {
			t.Fatalf("override must replace the baked default, got %v", got)
		}
	})

	t.Run("legacy AUTH_AUDIENCE widens, never narrows", func(t *testing.T) {
		t.Setenv("GATEWAY_ALLOWED_AUDIENCES", "")
		t.Setenv("AUTH_AUDIENCE", "https://api.hanzo.ai")
		got := AudiencesFromEnv()
		// Folding in a value already present must not drop the client_ids.
		if !contains(got, "hanzo-app") || !contains(got, "https://api.hanzo.ai") {
			t.Fatalf("legacy fold collapsed the allowlist: %v", got)
		}
	})
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
