package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// stubResolver lets tests script KMS responses without hitting the network.
type stubResolver struct {
	out []byte
	err error
}

func (s stubResolver) FetchRoutes(path string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func resetResolver(t *testing.T, r KMSResolver) {
	t.Helper()
	prev := SetKMSResolver(r)
	t.Cleanup(func() { SetKMSResolver(prev) })
}

// withEnv sets env vars for the duration of the subtest and restores them.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	saved := map[string]*string{}
	for k := range kv {
		if v, ok := os.LookupEnv(k); ok {
			saved[k] = &v
		} else {
			saved[k] = nil
		}
	}
	for k, v := range kv {
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
	}
	t.Cleanup(func() {
		for k, v := range saved {
			if v == nil {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, *v)
			}
		}
	})
}

const sampleRoutesYAML = `
routes:
  example.com:
    - prefix: /api
      backend: http://api.example.internal:8080
redirects:
  www.example.com: https://example.com
subdomains:
  ".tenant.example.com": http://tenants.internal:9000
`

func TestLoadRoutesFromEnv_KMSPath_UsesResolver(t *testing.T) {
	resetResolver(t, stubResolver{out: []byte(sampleRoutesYAML)})
	withEnv(t, map[string]string{
		"GATEWAY_ROUTES_KMS_PATH": "gateway/routes",
		"GATEWAY_ROUTES_FILE":     "",
		// Disable HTTP resolver auto-wire so stub is honored.
		"GATEWAY_KMS_ENDPOINT": "",
	})

	if err := loadRoutesFromEnv(); err != nil {
		t.Fatalf("loadRoutesFromEnv: %v", err)
	}

	routes.mu.RLock()
	got, ok := routes.exactRoutes["example.com"]
	redirects := routes.redirects
	subs := routes.subProxies
	routes.mu.RUnlock()

	if !ok {
		t.Fatalf("expected example.com to be loaded from KMS payload")
	}
	if len(got) != 1 || got[0].prefix != "/api" {
		t.Fatalf("expected /api prefix, got %+v", got)
	}
	if redirects["www.example.com"] != "https://example.com" {
		t.Fatalf("expected www.example.com redirect, got %+v", redirects)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subdomain proxy, got %d", len(subs))
	}
}

func TestLoadRoutesFromEnv_KMSError_Surfaces(t *testing.T) {
	wantErr := errors.New("kms: 500 backend down")
	resetResolver(t, stubResolver{err: wantErr})
	withEnv(t, map[string]string{
		"GATEWAY_ROUTES_KMS_PATH": "gateway/routes",
		"GATEWAY_KMS_ENDPOINT":    "",
	})

	err := loadRoutesFromEnv()
	if err == nil || !strings.Contains(err.Error(), "kms: 500") {
		t.Fatalf("expected KMS error to surface, got %v", err)
	}
}

func TestLoadRoutesFromEnv_KMSMalformedYAML_Surfaces(t *testing.T) {
	resetResolver(t, stubResolver{out: []byte("this is: not: valid: yaml: ::\n  -")})
	withEnv(t, map[string]string{
		"GATEWAY_ROUTES_KMS_PATH": "gateway/routes",
		"GATEWAY_KMS_ENDPOINT":    "",
	})

	err := loadRoutesFromEnv()
	if err == nil {
		t.Fatalf("expected malformed YAML error, got nil")
	}
	if !strings.Contains(err.Error(), "kms routes payload invalid") {
		t.Fatalf("expected wrapped invalid-payload error, got %v", err)
	}
}

func TestLoadRoutesFromEnv_NoKMSPath_FallsBackToFile(t *testing.T) {
	// Write a temp routes file.
	dir := t.TempDir()
	path := dir + "/routes.yaml"
	if err := os.WriteFile(path, []byte(sampleRoutesYAML), 0o600); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}

	// Resolver should NOT be called when GATEWAY_ROUTES_KMS_PATH is empty.
	resetResolver(t, stubResolver{err: errors.New("resolver must not be invoked")})
	withEnv(t, map[string]string{
		"GATEWAY_ROUTES_KMS_PATH": "",
		"GATEWAY_ROUTES_FILE":     path,
		"GATEWAY_KMS_ENDPOINT":    "",
	})

	if err := loadRoutesFromEnv(); err != nil {
		t.Fatalf("loadRoutesFromEnv (file fallback): %v", err)
	}
	routes.mu.RLock()
	_, ok := routes.exactRoutes["example.com"]
	routes.mu.RUnlock()
	if !ok {
		t.Fatalf("expected file fallback to populate routes")
	}
}

func TestNoopKMSResolver_AlwaysErrs(t *testing.T) {
	if _, err := (noopKMSResolver{}).FetchRoutes("anything"); err == nil {
		t.Fatalf("expected noop resolver to err")
	}
}

func TestNewHTTPKMSResolverFromEnv_MissingCreds_Disabled(t *testing.T) {
	withEnv(t, map[string]string{
		"GATEWAY_KMS_ENDPOINT":      "https://kms.example",
		"GATEWAY_KMS_CLIENT_ID":     "",
		"GATEWAY_KMS_CLIENT_SECRET": "",
		"IAM_CLIENT_ID":             "",
		"IAM_CLIENT_SECRET":         "",
	})
	if _, ok := newHTTPKMSResolverFromEnv(); ok {
		t.Fatalf("expected resolver disabled when credentials missing")
	}
}

func TestNewHTTPKMSResolverFromEnv_NoEndpoint_Disabled(t *testing.T) {
	withEnv(t, map[string]string{
		"GATEWAY_KMS_ENDPOINT":      "",
		"GATEWAY_KMS_CLIENT_ID":     "id",
		"GATEWAY_KMS_CLIENT_SECRET": "secret",
	})
	if _, ok := newHTTPKMSResolverFromEnv(); ok {
		t.Fatalf("expected resolver disabled when endpoint missing")
	}
}

// TestHTTPKMSResolver_FetchRoutes_RoundTrip exercises the auth + fetch flow
// against a stub that speaks the luxfi/kms contract. The stub registers ONLY
// the canonical paths, so a regression back to the Infisical shape
// (/api/v1/auth/universal-auth/login, /api/v3/secrets/raw/...) fails here
// rather than in production — which is where it hid last time, behind an
// embedded SPA that answered every unmatched path with 200 text/html.
func TestHTTPKMSResolver_FetchRoutes_RoundTrip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/kms/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ ClientId, ClientSecret string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ClientId != "id" || body.ClientSecret != "secret" {
			t.Fatalf("login credentials not forwarded: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "test-token"})
	})
	// {rest...} is split at its LAST slash into (path, name): "gateway/routes"
	// must arrive as path "gateway", name "routes". The URL names NO org —
	// the server scopes the read to the bearer's org; here the bearer itself
	// (minted by the login above) is the whole proof of identity.
	mux.HandleFunc("GET /v1/kms/secrets/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("missing/wrong bearer: %q", got)
		}
		if got := r.PathValue("rest"); got != "gateway/routes" {
			t.Fatalf("rest = %q, want %q (path separators must survive escaping)", got, "gateway/routes")
		}
		if got := r.URL.Query().Get("env"); got != "default" {
			t.Fatalf("env = %q, want the default", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"value": sampleRoutesYAML},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	withEnv(t, map[string]string{
		"GATEWAY_KMS_ENDPOINT":      srv.URL,
		"GATEWAY_KMS_CLIENT_ID":     "id",
		"GATEWAY_KMS_CLIENT_SECRET": "secret",
	})

	r, ok := newHTTPKMSResolverFromEnv()
	if !ok {
		t.Fatalf("expected resolver enabled")
	}
	data, err := r.FetchRoutes("gateway/routes")
	if err != nil {
		t.Fatalf("FetchRoutes: %v", err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Fatalf("unexpected payload: %s", data)
	}
}

// A bare name has no path segment, and the server would answer 400. Catch it
// in the client with a message that says what to write instead.
func TestHTTPKMSResolver_RejectsPathWithoutName(t *testing.T) {
	withEnv(t, map[string]string{
		"GATEWAY_KMS_ENDPOINT":      "https://api.hanzo.ai",
		"GATEWAY_KMS_CLIENT_ID":     "id",
		"GATEWAY_KMS_CLIENT_SECRET": "secret",
	})
	r, ok := newHTTPKMSResolverFromEnv()
	if !ok {
		t.Fatalf("expected resolver enabled")
	}
	_, err := r.FetchRoutes("routes")
	if err == nil {
		t.Fatal("want an error for a path with no name segment")
	}
	if !strings.Contains(err.Error(), "path and a name") {
		t.Fatalf("error should say what is missing, got: %v", err)
	}
}

func TestSetKMSResolver_NilRestoresNoop(t *testing.T) {
	prev := SetKMSResolver(stubResolver{out: []byte("ok")})
	t.Cleanup(func() { SetKMSResolver(prev) })

	SetKMSResolver(nil)
	if _, err := kmsResolver.FetchRoutes("x"); err == nil {
		t.Fatalf("expected noop resolver to err after nil reset")
	}
}
