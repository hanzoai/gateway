package main

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

	"github.com/hanzoai/gateway/v2/token"
)

// The admin-api gate admits a SuperAdmin and nothing else, on both doors: a
// bearer JWT is asked authz.Claims.Sudo (a person whose home org, orgs[0], is
// admin), and a browser session is asked for the verdict the server states
// (isSuperAdmin on /v1/ai/account). The `owner` CLAIM is the org of whichever
// application minted the token, so it is never the question.

const sudoIssuer = "https://hanzo.id"

type signer struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) }))
	t.Cleanup(srv.Close)
	return &signer{key: key, srv: srv}
}

func (s *signer) sign(t *testing.T, shape func(*authz.Claims)) string {
	t.Helper()
	now := time.Now()
	c := authz.Claims{Owner: "hanzo", Name: "root"}
	c.Issuer, c.Subject = sudoIssuer, "u-1"
	c.Audience = jwt.ClaimStrings{"hanzo-admin"}
	c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute)), jwt.NewNumericDate(now.Add(10*time.Minute))
	shape(&c)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	raw, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bearerGet(srv *server, tok string) int {
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.gate(srv.handleMe)(rec, req)
	return rec.Code
}

func TestGate_BearerIsAskedSudo(t *testing.T) {
	s := newSigner(t)
	cfg := &config{validator: token.NewValidator(token.Config{JWKSURL: s.srv.URL, Issuers: []string{sudoIssuer}})}
	srv := &server{cfg: cfg, agg: &aggregator{cfg: cfg}}

	cases := []struct {
		name  string
		shape func(*authz.Claims)
		want  int
	}{
		{"a person whose home org is admin", func(c *authz.Claims) {
			c.Orgs = []authz.Membership{{Org: authz.AdminOrg, Role: authz.Owner}}
		}, http.StatusOK},
		{"a brand person signed in through an admin-org application", func(c *authz.Claims) {
			c.Owner, c.Orgs = authz.AdminOrg, []authz.Membership{{Org: "hanzo", Role: authz.Owner}}
		}, http.StatusForbidden},
		{"a brand person holding an admin membership", func(c *authz.Claims) {
			c.Orgs = []authz.Membership{{Org: "hanzo", Role: authz.Owner}, {Org: authz.AdminOrg, Role: authz.Admin}}
		}, http.StatusForbidden},
		{"an admin-org program", func(c *authz.Claims) {
			c.Owner, c.Type = authz.AdminOrg, authz.Program
		}, http.StatusForbidden},
		{"an org named Admin", func(c *authz.Claims) {
			c.Owner, c.Orgs = "Admin", []authz.Membership{{Org: "Admin", Role: authz.Owner}}
		}, http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := bearerGet(srv, s.sign(t, tc.shape)); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestGate_SessionIsAskedTheServersVerdict(t *testing.T) {
	cases := []struct {
		name    string
		account map[string]any
		want    int
	}{
		{"the server says SuperAdmin", map[string]any{"owner": "admin", "name": "root", "type": "normal-user", "isSuperAdmin": true}, http.StatusOK},
		{"owner admin, but the server says not SuperAdmin", map[string]any{"owner": "admin", "name": "root", "type": "normal-user", "isSuperAdmin": false}, http.StatusForbidden},
		{"an admin-org program", map[string]any{"owner": "admin", "name": "bot", "type": "application"}, http.StatusForbidden},
		{"an org admin", map[string]any{"owner": "acme", "name": "dave", "isAdmin": true, "type": "normal-user"}, http.StatusForbidden},
		{"a forbidden account the server calls SuperAdmin", map[string]any{"owner": "admin", "name": "root", "isForbidden": true, "isSuperAdmin": true}, http.StatusForbidden},
	}
	for _, tc := range cases {
		cloud := fakeCloudAPI(t, tc.account)
		idp := fakeIAM(t)
		srv := newTestServer(cloud.URL, idp.URL)
		if got := gatedGet(srv, srv.handleMe, "/v1/admin/me").Code; got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
		cloud.Close()
		idp.Close()
	}
}
