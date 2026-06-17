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

func TestStripIdentityHeaders_LegacyAndVendor(t *testing.T) {
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
