// Copyright © 2026 Hanzo AI. MIT License.

package gateway

// fixtures_test.go is the signing identity and the claim shapes every auth test
// in this package mints with — and it is UNTAGGED on purpose.
//
// The gin-driven suites are `legacy`-tagged (that build is what the shipping
// image runs and the only one where a gin transport exists), while the zip
// suites run untagged. A fixture that lived in either would be a fixture the
// other build cannot see, and the two halves would grow two signing identities:
// two ways to mint the one token this edge validates. So the fixtures live here,
// in the intersection, and both halves mint the same way.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/authz"
	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"
)

// testJWKS holds a test RSA key pair and provides helpers for creating
// signed JWTs and serving a JWKS endpoint.
// testJWKS is a throwaway signing identity plus the key set that publishes it.
// It signs with golang-jwt, the SAME library IAM signs with and the one
// hanzoai/authz verifies with — a test that mints with a different library is
// testing a signer the estate does not run.
type testJWKS struct {
	key   *rsa.PrivateKey
	keyID string
}

func newTestJWKS(t *testing.T) *testJWKS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return &testJWKS{key: key, keyID: "test-key-1"}
}

// publicJWKS renders a key set the edge's reader accepts: kty/kid/use plus the
// modulus and exponent as base64url unsigned integers.
func publicJWKS(kid string, pub *rsa.PublicKey) []byte {
	data, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	return data
}

// jwksJSON returns the JWKS as JSON bytes (public key only).
func (tj *testJWKS) jwksJSON(t *testing.T) []byte {
	t.Helper()
	return publicJWKS(tj.keyID, &tj.key.PublicKey)
}

// serveJWKS starts an httptest.Server that serves the JWKS endpoint.
// The caller must defer server.Close().
func (tj *testJWKS) serveJWKS(t *testing.T) *httptest.Server {
	t.Helper()
	data := tj.jwksJSON(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

// signToken signs claims under this identity's key, naming the key in the header.
// The kid is not optional: authz.Verify refuses a token that names no key rather
// than trying every key in a set, which is how a reader ends up accepting a
// signature from a key the token never claimed.
// signToken signs either a typed claim set or a bare claim MAP. The map form
// exists so a test can mint a shape no struct would produce — a missing issuer,
// an unexpected claim, a wrong type — which is what a hostile token looks like.
func (tj *testJWKS) signToken(t *testing.T, claims any) string {
	t.Helper()
	return signAs(t, tj.key, tj.keyID, claimsOf(t, claims))
}

func claimsOf(t *testing.T, c any) jwt.Claims {
	t.Helper()
	switch v := c.(type) {
	case jwt.Claims:
		return v
	case map[string]any:
		return jwt.MapClaims(v)
	}
	t.Fatalf("cannot sign claims of type %T", c)
	return nil
}

// signAs signs claims under an arbitrary key and kid — the shape an attacker's
// token takes when it names a real key it does not hold.
func signAs(t *testing.T, key *rsa.PrivateKey, kid string, claims any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsOf(t, claims))
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return raw
}

// validClaims returns authz.Claims with valid issuer, audience, subject,
// owner, and expiry for use in tests.
func validClaims(issuer, audience string) authz.Claims {
	now := time.Now()
	return authz.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "alice",
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		// Owner is the APP's org, which is what IAM stamps there. The MEMBERSHIP SET is
		// the subject's own org and the only thing that confers authority — every user
		// token IAM signs carries it, home first (store.MemberOrgRefs), so a fixture
		// without it is a token that cannot exist.
		Owner: "hanzo",
		Name:  "Alice",
		Email: "alice@hanzo.ai",
		Orgs:  []authz.Membership{{Org: "hanzo", Role: authz.Member}},
	}
}

// iamToken is the claim MAP form — a token minted as data rather than through a
// struct, so a test can produce a shape no struct would (a missing issuer, an
// unexpected claim, a wrong type) which is what a hostile token looks like.
func iamToken(owner string, extra map[string]any) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": "https://hanzo.id", "sub": "uuid-alice",
		"aud": []string{"https://api.hanzo.ai"},
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"owner": owner, "email": "alice@hanzo.ai", "preferred_username": "alice",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// memberToken is the shape every user token IAM signs has: an owner AND the
// signed membership set, which is the only thing that confers an org. A fixture
// without `orgs` is a token that cannot exist (see validClaims).
func memberToken() map[string]any {
	return iamToken("hanzo", map[string]any{
		"orgs": []map[string]any{{"org": "hanzo", "role": "member"}},
	})
}

// edgeAuthConfig is the auth config the zip and gin edges are BOTH driven with:
// one JWKS, one issuer, one audience allowlist, no billing, auth REQUIRED (so a
// tokenless request is a refusal rather than an anonymous pass-through).
func edgeAuthConfig(jwksURL string) AuthConfig {
	return AuthConfig{
		Enabled:        true,
		JWKSURL:        jwksURL,
		Issuer:         "https://hanzo.id",
		Audiences:      []string{"https://api.hanzo.ai"},
		BillingEnabled: false,
		PublicPaths:    []string{"/healthz"},
		PublicHosts:    []string{"hanzo.id"},
		RequireAuth:    true,
	}
}

// edgeResult is one edge's answer, in the shape both edges can report.
type edgeResult struct {
	name        string
	status      int
	acao        string
	credentials string
	vary        string
}

// zipEdge runs the SAME request through the zip handler and reports the answer
// in the same shape, so the two are comparable as values.
func zipEdge(t *testing.T, h zip.Handler, method, path, host string, hdr map[string]string) edgeResult {
	t.Helper()
	z := zip.New(zip.Config{Logger: luxlog.New("test"), AppName: "gateway"})
	z.Use(h)
	z.All(path, func(c *zip.Ctx) error { return c.String(http.StatusOK, "") })

	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := z.Fiber().Test(req)
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	return edgeResult{
		name:        "zip",
		status:      resp.StatusCode,
		acao:        resp.Header.Get("Access-Control-Allow-Origin"),
		credentials: resp.Header.Get("Access-Control-Allow-Credentials"),
		vary:        resp.Header.Get("Vary"),
	}
}
