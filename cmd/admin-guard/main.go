// admin-guard is the single forward-auth gate that restricts Hanzo's RAW
// global-admin surfaces (platform.hanzo.ai, studio, commerce-admin, the raw
// KMS admin UI, the IAM management UI) to GLOBAL ADMINS ONLY — an IAM user
// whose org (`owner`) is the admin org (IAM `IsGlobalAdmin`: owner == AdminOrg).
//
// It is consumed by hanzoai/ingress (Traefik) as a ForwardAuth middleware:
// the ingress forwards each request's headers to GET /__guard/verify and
// enforces the verdict.
//
//	verdict 2xx  → allow (caller is a global admin)
//	verdict 302  → redirect (caller is a non-admin → console.hanzo.ai;
//	               or anonymous → IAM PKCE login)
//
// One gate, one mechanism, every admin surface. Clients never reach a raw
// admin or a 403 dead-end: a non-admin is always sent to the unified client
// surface, console.hanzo.ai.
//
// Identity resolution is decomplected into three orthogonal sources, tried in
// order, all collapsing to one predicate (owner == AdminOrg):
//
//  1. the guard's own signed session cookie (set after a prior PKCE login) —
//     the browser fast path, shared across *.hanzo.ai via a parent-domain cookie;
//  2. a Bearer / Basic JWT validated through iamauth (the API path) — the JWT
//     already carries `owner`, so no IAM round-trip is needed;
//  3. an IAM session cookie, resolved by calling IAM get-account server-side
//     (the path for a browser that has an IAM session but no guard cookie yet).
//
// The login flow is standard OAuth2 Authorization-Code + PKCE against IAM
// (client_id default `hanzo-admin-guard`), mirroring oauth2-proxy.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/gateway/v2/iamauth"
)

// config holds the guard's runtime configuration, all from the environment so
// the same binary serves every cluster.
type config struct {
	// Listen address (forward-auth + login endpoints).
	addr string

	// IAM OAuth2 authority.
	iamPublic    string // browser-facing IAM base (e.g. https://hanzo.id)
	iamInternal  string // in-cluster IAM base for server-side calls (e.g. http://iam.hanzo.svc.cluster.local)
	clientID     string
	clientSecret string

	// AdminOrg is the global-admin org slug (IAM conf.AdminOrg). A caller is a
	// global admin iff their token/account `owner` equals this. Default "admin".
	adminOrg string

	// Where non-admins (and any non-actionable error) are sent — the unified
	// client surface.
	consoleURL string

	// cookieDomain scopes the guard session cookie so one admin login covers
	// every guarded *.hanzo.ai host (e.g. ".hanzo.ai").
	cookieDomain string
	cookieName   string
	cookieTTL    time.Duration

	// hmacKey signs the guard session + PKCE state cookies.
	hmacKey []byte

	// validator validates Bearer/Basic JWTs (issuer + audience + expiry) and
	// exposes claims.owner — the same edge validator the gateway uses.
	validator *iamauth.Validator
}

const (
	verifyPath   = "/__guard/verify"
	callbackPath = "/__guard/callback"
	logoutPath   = "/__guard/logout"
	healthPath   = "/__guard/healthz"

	stateCookie = "hanzo_admin_guard_state"
)

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc(verifyPath, cfg.handleVerify)
	mux.HandleFunc(callbackPath, cfg.handleCallback)
	mux.HandleFunc(logoutPath, cfg.handleLogout)

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("admin-guard listening on %s (adminOrg=%q console=%s cookieDomain=%s iam=%s)",
		cfg.addr, cfg.adminOrg, cfg.consoleURL, cfg.cookieDomain, cfg.iamPublic)
	log.Fatal(srv.ListenAndServe())
}

func loadConfig() *config {
	hmacKey := []byte(os.Getenv("GUARD_HMAC_KEY"))
	if len(hmacKey) < 16 {
		log.Fatal("GUARD_HMAC_KEY must be set to a random secret of >=16 bytes")
	}
	clientSecret := os.Getenv("IAM_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("IAM_CLIENT_SECRET must be set")
	}

	iamPublic := envOr("IAM_PUBLIC_URL", "https://hanzo.id")
	// iamauth validates against the JWKS issuer; reuse its env (AUTH_ISSUER /
	// AUTH_JWKS_URL) so the guard and gateway agree on the IAM authority.
	vcfg := iamauth.ConfigFromEnv()

	return &config{
		addr:         envOr("GUARD_ADDR", ":8080"),
		iamPublic:    iamPublic,
		iamInternal:  envOr("IAM_INTERNAL_URL", "https://iam.hanzo.ai"),
		clientID:     envOr("IAM_CLIENT_ID", "hanzo-admin-guard"),
		clientSecret: clientSecret,
		adminOrg:     envOr("IAM_ADMIN_ORG", "admin"),
		consoleURL:   envOr("CONSOLE_URL", "https://console.hanzo.ai"),
		cookieDomain: envOr("GUARD_COOKIE_DOMAIN", ".hanzo.ai"),
		cookieName:   envOr("GUARD_COOKIE_NAME", "hanzo_admin_guard"),
		cookieTTL:    envDuration("GUARD_COOKIE_TTL", 8*time.Hour),
		hmacKey:      hmacKey,
		validator:    iamauth.NewValidator(vcfg),
	}
}

// ----------------------------------------------------------------------------
// Forward-auth verdict
// ----------------------------------------------------------------------------

// handleVerify is the ForwardAuth target. It computes the original request URL
// from the X-Forwarded-* headers the ingress sets, then resolves the caller's
// org and renders one of three verdicts.
func (c *config) handleVerify(w http.ResponseWriter, r *http.Request) {
	orig := originalURL(r)

	// (1) Guard session cookie — the browser fast path.
	if owner, ok := c.sessionOwner(r); ok {
		c.decide(w, r, owner, orig)
		return
	}

	// (2) Bearer/Basic JWT — the API path. The JWT carries `owner` directly.
	if claims, err := c.validator.Validate(r); err == nil && claims != nil {
		c.decide(w, r, claims.Owner, orig)
		return
	} else if err != nil && err != iamauth.ErrNoToken {
		// A token was presented but did not validate. For an API caller, fail
		// closed with 401 (don't bounce a non-browser through a login redirect).
		if isAPIClient(r) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// Browser with a bad/expired bearer — fall through to interactive login.
	}

	// (3) IAM session cookie — resolve via IAM get-account server-side.
	if owner, ok := c.iamSessionOwner(r); ok {
		c.decide(w, r, owner, orig)
		return
	}

	// No identity at all.
	if isAPIClient(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	// Browser → start interactive IAM PKCE login.
	c.startLogin(w, r, orig)
}

// decide renders the allow/redirect verdict for a resolved org.
func (c *config) decide(w http.ResponseWriter, r *http.Request, owner, orig string) {
	if owner != "" && owner == c.adminOrg {
		// Global admin — allow. Pass the org downstream for app-side auditing.
		w.Header().Set("X-Org-Id", owner)
		w.Header().Set("X-Admin-Guard", "allow")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Authenticated, but NOT a global admin → unified client surface.
	if isAPIClient(r) {
		http.Error(w, "global admin required", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, c.consoleURL, http.StatusFound)
}

// ----------------------------------------------------------------------------
// Identity source (1): the guard's own signed session cookie
// ----------------------------------------------------------------------------

// sessionOwner returns the org from a valid, unexpired guard session cookie.
// Cookie value: base64(owner|expiryUnix) "." base64(HMAC). Tamper-evident and
// time-bounded; no server-side store needed.
func (c *config) sessionOwner(r *http.Request) (string, bool) {
	ck, err := r.Cookie(c.cookieName)
	if err != nil {
		return "", false
	}
	payload, ok := c.verifySigned(ck.Value)
	if !ok {
		return "", false
	}
	owner, expStr, ok := strings.Cut(payload, "|")
	if !ok {
		return "", false
	}
	expUnix, err := parseInt(expStr)
	if err != nil || time.Now().Unix() > expUnix {
		return "", false
	}
	return owner, owner != ""
}

func (c *config) setSession(w http.ResponseWriter, owner string) {
	exp := time.Now().Add(c.cookieTTL)
	payload := fmt.Sprintf("%s|%d", owner, exp.Unix())
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    c.sign(payload),
		Path:     "/",
		Domain:   c.cookieDomain,
		Expires:  exp,
		MaxAge:   int(c.cookieTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *config) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   c.cookieDomain,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ----------------------------------------------------------------------------
// Identity source (3): IAM session cookie → get-account
// ----------------------------------------------------------------------------

// iamSessionOwner forwards the inbound cookies to IAM get-account and reads the
// authenticated user's `owner`. This covers a browser that holds an IAM SSO
// session but has not yet been issued a guard cookie.
func (c *config) iamSessionOwner(r *http.Request) (string, bool) {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.iamInternal, "/")+"/v1/iam/get-account", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false
	}
	return ownerFromAccount(body)
}

// ownerFromAccount extracts the user's org from an IAM get-account response.
// IAM (Casdoor) get-account returns the User object either at the top level or
// wrapped under `data`; the org slug is the `owner` field. An error/unsigned
// response has status:"error" and no owner.
func ownerFromAccount(body []byte) (string, bool) {
	var top struct {
		Status string `json:"status"`
		Owner  string `json:"owner"`
		Data   struct {
			Owner string `json:"owner"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return "", false
	}
	if top.Status == "error" {
		return "", false
	}
	if top.Owner != "" {
		return top.Owner, true
	}
	if top.Data.Owner != "" {
		return top.Data.Owner, true
	}
	return "", false
}

// ----------------------------------------------------------------------------
// OAuth2 Authorization-Code + PKCE login
// ----------------------------------------------------------------------------

// startLogin redirects the browser to IAM's authorize endpoint with a PKCE
// challenge, stashing the verifier + the post-login return URL in a short-lived
// signed state cookie.
func (c *config) startLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	verifier := randString(48)
	challenge := pkceChallenge(verifier)
	nonce := randString(16)

	// state cookie payload: nonce|verifier|returnTo (signed, 10-minute life).
	statePayload := strings.Join([]string{nonce, verifier, returnTo}, "\x1f")
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    c.sign(statePayload),
		Path:     "/",
		Domain:   c.cookieDomain,
		MaxAge:   600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	q := url.Values{}
	q.Set("client_id", c.clientID)
	// Pin the reserved admin org so a user who is a member of BOTH a tenant org
	// and the admin org resolves to their admin-org identity (owner==adminOrg),
	// which handleCallback requires. Without this, a login defaults to the user's
	// home org and the guard denies + bounces to the tenant console.
	q.Set("organization", c.adminOrg)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", c.callbackURI(r))
	q.Set("state", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	authorize := strings.TrimRight(c.iamPublic, "/") + "/v1/iam/oauth/authorize?" + q.Encode()
	http.Redirect(w, r, authorize, http.StatusFound)
}

// handleCallback completes the PKCE exchange, derives the org, sets the guard
// session, and returns the browser to where it started.
func (c *config) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	gotState := r.URL.Query().Get("state")
	if code == "" || gotState == "" {
		http.Error(w, "missing code/state", http.StatusBadRequest)
		return
	}
	ck, err := r.Cookie(stateCookie)
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	payload, ok := c.verifySigned(ck.Value)
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(payload, "\x1f", 3)
	if len(parts) != 3 || subtleNE(parts[0], gotState) {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	verifier, returnTo := parts[1], parts[2]
	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", Domain: c.cookieDomain, MaxAge: -1, Secure: true, HttpOnly: true})

	owner, err := c.exchange(r.Context(), code, verifier, c.callbackURI(r))
	if err != nil {
		log.Printf("admin-guard: token exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	if owner != c.adminOrg {
		// Authenticated non-admin: do NOT set an admin session; send to console.
		http.Redirect(w, r, c.consoleURL, http.StatusFound)
		return
	}
	c.setSession(w, owner)
	if returnTo == "" || !strings.HasPrefix(returnTo, "https://") {
		returnTo = c.consoleURL
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// exchange swaps the auth code for tokens and resolves the org from the ID
// token (validated via iamauth) or, failing that, the userinfo endpoint.
func (c *config) exchange(ctx context.Context, code, verifier, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code_verifier", verifier)

	tokenURL := strings.TrimRight(c.iamInternal, "/") + "/v1/iam/oauth/access_token"
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, truncate(body, 256))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	// Prefer the ID token's validated `owner` claim.
	if tok.IDToken != "" {
		if claims, verr := c.validator.ValidateRaw(tok.IDToken); verr == nil && claims.Owner != "" {
			return claims.Owner, nil
		}
	}
	if tok.AccessToken != "" {
		if claims, verr := c.validator.ValidateRaw(tok.AccessToken); verr == nil && claims.Owner != "" {
			return claims.Owner, nil
		}
	}
	// Fallback: call userinfo with the access token.
	if tok.AccessToken != "" {
		if owner, ok := c.userinfoOwner(ctx, tok.AccessToken); ok {
			return owner, nil
		}
	}
	return "", fmt.Errorf("could not resolve owner from token or userinfo")
}

func (c *config) userinfoOwner(ctx context.Context, accessToken string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.iamInternal, "/")+"/v1/iam/oauth/userinfo", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ui struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(body, &ui); err != nil {
		return "", false
	}
	return ui.Owner, ui.Owner != ""
}

func (c *config) handleLogout(w http.ResponseWriter, r *http.Request) {
	c.clearSession(w)
	http.Redirect(w, r, c.consoleURL, http.StatusFound)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// originalURL reconstructs the URL the client requested from the ingress's
// X-Forwarded-* headers (Traefik forward-auth sets these).
func originalURL(r *http.Request) string {
	proto := firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), "https")
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	uri := firstNonEmpty(r.Header.Get("X-Forwarded-Uri"), r.URL.RequestURI())
	return proto + "://" + host + uri
}

// callbackURI is the absolute redirect_uri for the host being guarded. Each
// guarded host serves the guard's callback path through the same ingress route,
// so the callback lands back on the originating host (and its IAM client must
// allowlist https://<host>/__guard/callback).
func (c *config) callbackURI(r *http.Request) string {
	proto := firstNonEmpty(r.Header.Get("X-Forwarded-Proto"), "https")
	host := firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host)
	return proto + "://" + host + callbackPath
}

// isAPIClient reports whether the caller looks like a non-browser API client
// (so we fail closed with a status code instead of an interactive redirect).
func isAPIClient(r *http.Request) bool {
	if iamauth.BearerToken(r) != "" || iamauth.BasicToken(r) != "" {
		return true
	}
	accept := r.Header.Get("X-Forwarded-Accept")
	if accept == "" {
		accept = r.Header.Get("Accept")
	}
	// A browser navigation sends Accept: text/html...; pure JSON/无 Accept = API.
	if accept != "" && !strings.Contains(accept, "text/html") {
		return true
	}
	return false
}

func (c *config) sign(payload string) string {
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (c *config) verifySigned(v string) (string, bool) {
	b64payload, sig, ok := strings.Cut(v, ".")
	if !ok {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(b64payload)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(payload)
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return "", false
	}
	return string(payload), true
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("crypto/rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			return parsed
		}
	}
	return d
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseInt(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscan(s, &n)
	return n, err
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

func subtleNE(a, b string) bool { return !hmac.Equal([]byte(a), []byte(b)) }
