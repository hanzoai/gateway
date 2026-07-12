package iamauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func req(headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://goproxy.hanzo.ai/golang.org/x/mod/@v/list", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestBearerToken(t *testing.T) {
	if got := BearerToken(req(map[string]string{"Authorization": "Bearer abc.def.ghi"})); got != "abc.def.ghi" {
		t.Fatalf("Bearer: got %q", got)
	}
	if got := BearerToken(req(map[string]string{"X-Authorization": "Bearer xyz"})); got != "xyz" {
		t.Fatalf("X-Authorization Bearer: got %q", got)
	}
	if got := BearerToken(req(map[string]string{"Authorization": basic("u", "p")})); got != "" {
		t.Fatalf("Basic must not parse as Bearer: got %q", got)
	}
}

// The canonical `go`/.netrc proxy auth path: credential arrives as HTTP
// Basic, token in the password field.
func TestBasicToken_PasswordIsToken(t *testing.T) {
	if got := BasicToken(req(map[string]string{"Authorization": basic("z@hanzo.ai", "the-iam-jwt")})); got != "the-iam-jwt" {
		t.Fatalf("password token: got %q", got)
	}
	// Empty password → fall back to username (token-as-username clients).
	if got := BasicToken(req(map[string]string{"Authorization": basic("the-iam-jwt", "")})); got != "the-iam-jwt" {
		t.Fatalf("username fallback: got %q", got)
	}
	if got := BasicToken(req(map[string]string{"Authorization": "Bearer abc"})); got != "" {
		t.Fatalf("Bearer must not parse as Basic: got %q", got)
	}
	if got := BasicToken(req(map[string]string{"Authorization": "Basic not-base64!!"})); got != "" {
		t.Fatalf("bad base64 must yield empty: got %q", got)
	}
}

func TestExtractToken_Precedence(t *testing.T) {
	// Bearer wins over Basic.
	r := req(map[string]string{"Authorization": "Bearer bearer-wins"})
	r.Header.Add("X-Authorization", "Bearer ignored")
	if got := ExtractToken(r); got != "bearer-wins" {
		t.Fatalf("precedence Bearer: got %q", got)
	}
	// Basic when no Bearer.
	if got := ExtractToken(req(map[string]string{"Authorization": basic("u", "basic-token")})); got != "basic-token" {
		t.Fatalf("precedence Basic: got %q", got)
	}
	// Cookie when neither.
	r = req(nil)
	r.AddCookie(&http.Cookie{Name: "iam_access_token", Value: "cookie-token"})
	if got := ExtractToken(r); got != "cookie-token" {
		t.Fatalf("precedence cookie: got %q", got)
	}
}

func TestIsAPIKey(t *testing.T) {
	for _, k := range []string{"hk-x", "sk-x", "fw_x", "hz_x", "pk-x"} {
		if !IsAPIKey(k) {
			t.Fatalf("%q should be an API key", k)
		}
	}
	if IsAPIKey("eyJhbGci.jwt.sig") {
		t.Fatal("JWT must not be treated as API key")
	}
}

// Strip-list MUST cover every minted header — the trust boundary contract.
func TestStripList_CoversAllMinted(t *testing.T) {
	for _, h := range MintedIdentityHeaders {
		r := req(map[string]string{h: "forged"})
		StripIdentityHeaders(r)
		if r.Header.Get(h) != "" {
			t.Fatalf("minted header %q not stripped", h)
		}
	}
}

// TestStripIdentityHeaders_NeutralExactAndVendorBackstop: neutral identity headers
// are stripped by exact name; a NON-identity header survives; and the gateway's
// Go-side defensive backstop still deletes any stray vendor-prefixed header
// (brand-neutral: it only deletes vendor junk, on every deployment). The ingress
// strip needs no wildcard because identity headers are all neutral now.
func TestStripIdentityHeaders_NeutralExactAndVendorBackstop(t *testing.T) {
	r := req(map[string]string{
		"X-User-Id":     "forged",
		"X-Org-Id":      "forged",
		"X-User-Role":   "admin",
		"X-Tenant-Id":   "t",
		"X-IAM-Foo":     "x",
		"X-HANZO-Bar":   "y",
		"X-Real-Header": "keep",
	})
	StripIdentityHeaders(r)
	for _, h := range []string{"X-User-Id", "X-Org-Id", "X-User-Role", "X-Tenant-Id", "X-Iam-Foo", "X-Hanzo-Bar"} {
		if r.Header.Get(h) != "" {
			t.Fatalf("header %q should be stripped", h)
		}
	}
	if r.Header.Get("X-Real-Header") != "keep" {
		t.Fatal("non-identity header must survive")
	}
}

func TestInjectIdentity(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "hanzo", Email: "z@hanzo.ai", IsAdmin: true})
	// UserID falls back to preferred_username/name when sub empty; here all empty.
	if r.Header.Get("X-Org-Id") != "hanzo" {
		t.Fatalf("X-Org-Id: got %q", r.Header.Get("X-Org-Id"))
	}
	if r.Header.Get("X-User-Email") != "z@hanzo.ai" {
		t.Fatalf("X-User-Email: got %q", r.Header.Get("X-User-Email"))
	}
	if r.Header.Get("X-User-IsAdmin") != "true" {
		t.Fatalf("X-User-IsAdmin: got %q", r.Header.Get("X-User-IsAdmin"))
	}
	// An ORG-level admin (owner="hanzo") is NOT a platform admin: the superadmin
	// header (the money authority commerce reads) must NOT be minted.
	if r.Header.Get("X-User-IsGlobalAdmin") != "" {
		t.Fatalf("X-User-IsGlobalAdmin minted for org-level admin: got %q", r.Header.Get("X-User-IsGlobalAdmin"))
	}
	// No project claim ⟹ default project ⟹ X-Project-Id omitted (present iff
	// a non-default project is in scope), preserving single-project behavior.
	if v := r.Header.Get("X-Project-Id"); v != "" {
		t.Fatalf("X-Project-Id must be omitted for the default project, got %q", v)
	}
}

// TestInjectIdentity_NoPlatformAdminHeader proves InjectIdentity mints NO platform-
// admin boolean header. Platform sudo is org == AdminOrg (carried by X-Org-Id), with
// no boolean — so even an admin-org principal gets no X-User-IsGlobalAdmin.
func TestInjectIdentity_NoPlatformAdminHeader(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "admin", IsAdmin: true})
	if v := r.Header.Get("X-User-IsGlobalAdmin"); v != "" {
		t.Fatalf("X-User-IsGlobalAdmin must never be minted (platform sudo = org==admin), got %q", v)
	}
	// The platform-sudo signal is the org itself, carried by X-Org-Id.
	if got := r.Header.Get("X-Org-Id"); got != "admin" {
		t.Fatalf("X-Org-Id: got %q want \"admin\" (the platform-sudo signal)", got)
	}
}

// TestClaims_PlatformSudo pins the ONE platform-sudo predicate: membership in the
// reserved AdminOrg (owner=="admin"), case/space-insensitive. There is no boolean
// flag; a plain org-level IsAdmin (an org owner) must NOT qualify — that was the
// free-money hole. Mirrors commerce/cloud/iam gating on org == AdminOrg.
func TestClaims_PlatformSudo(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		want   bool
	}{
		{"nil", nil, false},
		{"admin-org", &Claims{Owner: "admin"}, true},
		{"admin-org-mixedcase", &Claims{Owner: "Admin"}, true},
		{"admin-org-spaces", &Claims{Owner: " admin "}, true},
		{"org-admin-not-platform", &Claims{Owner: "maxpower", IsAdmin: true}, false},
		{"plain-user", &Claims{Owner: "hanzo"}, false},
	}
	for _, tc := range cases {
		if got := tc.claims.PlatformSudo(); got != tc.want {
			t.Fatalf("%s: PlatformSudo()=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestInjectIdentity_Project: a non-default `project` claim is minted into
// X-Project-Id exactly like `owner`→X-Org-Id; the literal default is omitted.
func TestInjectIdentity_Project(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "acme", Project: "research"})
	if got := r.Header.Get("X-Project-Id"); got != "research" {
		t.Fatalf("X-Project-Id: got %q, want %q", got, "research")
	}
	// The literal default project mints nothing (absent header ⟺ default scope).
	r = req(nil)
	InjectIdentity(r, &Claims{Owner: "acme", Project: DefaultProject})
	if got := r.Header.Get("X-Project-Id"); got != "" {
		t.Fatalf("X-Project-Id must be omitted for %q, got %q", DefaultProject, got)
	}
}

func TestClaims_UserIDFallback(t *testing.T) {
	c := &Claims{PreferredUsername: "alice"}
	if c.UserID() != "alice" {
		t.Fatalf("preferred_username fallback: got %q", c.UserID())
	}
	c = &Claims{Name: "Bob"}
	if c.UserID() != "Bob" {
		t.Fatalf("name fallback: got %q", c.UserID())
	}
}
