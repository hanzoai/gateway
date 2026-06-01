package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// KMSResolver fetches a routing-config secret payload from a Hanzo KMS path.
// The default implementation is a noop; activated implementations are wired
// in by setting GATEWAY_ROUTES_KMS_PATH (and the resolver-specific env vars
// documented on each implementation).
//
// Implementations MUST return the raw YAML bytes for the routes config; the
// caller (loadRoutesFromEnv) is responsible for parsing them via yaml.Unmarshal.
type KMSResolver interface {
	// FetchRoutes returns the raw YAML payload at the given KMS path.
	// An empty path is a programmer error; resolvers should return an error.
	FetchRoutes(path string) ([]byte, error)
}

// noopKMSResolver is the default resolver. It always returns an error so that
// loadRoutesFromEnv knows KMS is not configured and can fall back to the file
// loader. We never call this when GATEWAY_ROUTES_KMS_PATH is unset.
type noopKMSResolver struct{}

func (noopKMSResolver) FetchRoutes(string) ([]byte, error) {
	return nil, fmt.Errorf("kms: no resolver configured (set GATEWAY_KMS_ENDPOINT + IAM_CLIENT_ID/SECRET, or inject via SetKMSResolver)")
}

// httpKMSResolver speaks the Hanzo KMS HTTP contract documented in
// hanzoai/base/plugins/platform/kms.go: authenticate via Universal-Auth
// (POST /api/v1/auth/universal-auth/login with IAM_CLIENT_ID + IAM_CLIENT_SECRET),
// then GET /api/v3/secrets/raw/<path> and read .secret.secretValue.
//
// Env contract:
//   - GATEWAY_KMS_ENDPOINT      (e.g. https://kms.hanzo.ai)
//   - GATEWAY_KMS_CLIENT_ID     (falls back to IAM_CLIENT_ID)
//   - GATEWAY_KMS_CLIENT_SECRET (falls back to IAM_CLIENT_SECRET)
type httpKMSResolver struct {
	endpoint     string
	clientID     string
	clientSecret string
	client       *http.Client
}

func newHTTPKMSResolverFromEnv() (KMSResolver, bool) {
	endpoint := os.Getenv("GATEWAY_KMS_ENDPOINT")
	if endpoint == "" {
		return nil, false
	}
	clientID := os.Getenv("GATEWAY_KMS_CLIENT_ID")
	if clientID == "" {
		clientID = os.Getenv("IAM_CLIENT_ID")
	}
	clientSecret := os.Getenv("GATEWAY_KMS_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = os.Getenv("IAM_CLIENT_SECRET")
	}
	if clientID == "" || clientSecret == "" {
		return nil, false
	}
	return &httpKMSResolver{
		endpoint:     strings.TrimRight(endpoint, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       &http.Client{Timeout: 10 * time.Second},
	}, true
}

func (r *httpKMSResolver) FetchRoutes(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("kms: empty path")
	}
	token, err := r.authenticate()
	if err != nil {
		return nil, fmt.Errorf("kms: auth: %w", err)
	}
	endpoint := fmt.Sprintf("%s/api/v3/secrets/raw/%s", r.endpoint, url.PathEscape(path))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kms: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("kms: GET %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("kms: decode response: %w", err)
	}
	if result.Secret.SecretValue == "" {
		return nil, fmt.Errorf("kms: empty secret value for path %s", path)
	}
	return []byte(result.Secret.SecretValue), nil
}

func (r *httpKMSResolver) authenticate() (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"clientId":     r.clientID,
		"clientSecret": r.clientSecret,
	})
	req, err := http.NewRequest(http.MethodPost,
		r.endpoint+"/api/v1/auth/universal-auth/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("login returned %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return out.AccessToken, nil
}

// kmsResolver is the package-level resolver used by loadRoutesFromEnv.
// Tests inject a stub via SetKMSResolver; production code wires the HTTP
// resolver automatically when GATEWAY_KMS_ENDPOINT is set.
var kmsResolver KMSResolver = noopKMSResolver{}

// SetKMSResolver swaps the package-level KMS resolver. Intended for tests
// and for embedders that want to plug in a non-HTTP secret backend.
// Returns the previous resolver so callers can restore it.
func SetKMSResolver(r KMSResolver) KMSResolver {
	prev := kmsResolver
	if r == nil {
		kmsResolver = noopKMSResolver{}
	} else {
		kmsResolver = r
	}
	return prev
}

// initKMSResolverFromEnv installs the HTTP KMS resolver if GATEWAY_KMS_ENDPOINT
// (and credentials) are present. Safe to call multiple times; later calls
// overwrite earlier ones, matching env precedence.
func initKMSResolverFromEnv() {
	if r, ok := newHTTPKMSResolverFromEnv(); ok {
		kmsResolver = r
	}
}
