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

	// AdminOrg is the global-admin org slug (IAM conf.AdminOrg). A global admin
	// (owner == adminOrg) is ALWAYS approved. Default "admin".
	adminOrg string

	// Where UNAPPROVED (waitlisted) callers are sent — the viral waitlist landing.
	waitlistURL string

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

	stateCookie = "hanzo_waitlist_guard_state"
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
	log.Printf("waitlist-guard listening on %s (adminOrg=%q waitlist=%s cookieDomain=%s iam=%s)",
		cfg.addr, cfg.adminOrg, cfg.waitlistURL, cfg.cookieDomain, cfg.iamPublic)
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
		clientID:     envOr("IAM_CLIENT_ID", "hanzo-waitlist-guard"),
		clientSecret: clientSecret,
		adminOrg:     envOr("IAM_ADMIN_ORG", "admin"),
		waitlistURL:  envOr("WAITLIST_URL", "https://waitlist.hanzo.ai"),
		cookieDomain: envOr("GUARD_COOKIE_DOMAIN", ".hanzo.ai"),
		cookieName:   envOr("GUARD_COOKIE_NAME", "hanzo_waitlist_guard"),
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
// APPROVAL STATUS and renders one of three verdicts.
//
// This is the waitlist gate: an APPROVED identity is allowed onto the product
// surface; an UNAPPROVED (waitlisted) identity is bounced to the viral waitlist
// (browser) or 403'd (API); an anonymous browser is sent to IAM PKCE login.
func (c *config) handleVerify(w http.ResponseWriter, r *http.Request) {
	orig := originalURL(r)

	// (1) Guard session cookie — the browser fast path. The signed cookie encodes
	//     the approved verdict, so no IAM round-trip on the hot path.
	if owner, approved, ok := c.sessionOwner(r); ok {
		c.decide(w, r, owner, approved, orig)
		return
	}

	// (2) Bearer/Basic JWT — the API path. The JWT carries `owner`/`isAdmin` but
	//     NOT the live approval property (a token can lag an approval), so the
	//     authoritative status comes from IAM. Admins are always approved.
	if claims, err := c.validator.Validate(r); err == nil && claims != nil {
		approved := claims.IsAdmin || claims.Owner == c.adminOrg || c.iamUserApproved(r, claims.Owner+"/"+claims.Name)
		c.decide(w, r, claims.Owner, approved, orig)
		return
	} else if err != nil && err != iamauth.ErrNoToken {
		if isAPIClient(r) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// Browser with a bad/expired bearer — fall through to interactive login.
	}

	// (3) IAM session cookie — resolve owner + approval via IAM get-account.
	if owner, approved, ok := c.iamSessionApproval(r); ok {
		c.decide(w, r, owner, approved, orig)
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

// decide renders the allow/redirect verdict. APPROVED ⇒ allow; authenticated-
// but-unapproved ⇒ the viral waitlist (browser) / 403 (API).
func (c *config) decide(w http.ResponseWriter, r *http.Request, owner string, approved bool, orig string) {
	if approved {
		if owner != "" {
			w.Header().Set("X-Org-Id", owner)
		}
		w.Header().Set("X-Waitlist-Guard", "allow")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if isAPIClient(r) {
		http.Error(w, "account pending approval — join the waitlist", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, c.waitlistURL, http.StatusFound)
}

// ----------------------------------------------------------------------------
// Identity source (1): the guard's own signed session cookie
// ----------------------------------------------------------------------------

// sessionOwner returns the org + approved verdict from a valid, unexpired guard
// session cookie. Cookie value: base64(owner|approved|expiryUnix) "." base64(HMAC).
// Tamper-evident and time-bounded; no server-side store needed. The approved bit
// is bound into the signed payload so it cannot be forged.
func (c *config) sessionOwner(r *http.Request) (string, bool, bool) {
	ck, err := r.Cookie(c.cookieName)
	if err != nil {
		return "", false, false
	}
	payload, ok := c.verifySigned(ck.Value)
	if !ok {
		return "", false, false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 3 {
		return "", false, false
	}
	owner, approvedStr, expStr := parts[0], parts[1], parts[2]
	expUnix, err := parseInt(expStr)
	if err != nil || time.Now().Unix() > expUnix {
		return "", false, false
	}
	return owner, approvedStr == "1", owner != ""
}

func (c *config) setSession(w http.ResponseWriter, owner string, approved bool) {
	exp := time.Now().Add(c.cookieTTL)
	approvedBit := "0"
	if approved {
		approvedBit = "1"
	}
	payload := fmt.Sprintf("%s|%s|%d", owner, approvedBit, exp.Unix())
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

// iamSessionApproval forwards the inbound cookies to IAM get-account and reads
// the authenticated user's `owner` AND approval status in one round-trip. This
// covers a browser that holds an IAM SSO session but has not yet been issued a
// guard cookie.
func (c *config) iamSessionApproval(r *http.Request) (owner string, approved bool, ok bool) {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return "", false, false
	}
	body, ok := c.iamGet(r, strings.TrimRight(c.iamInternal, "/")+"/v1/iam/get-account", cookie)
	if !ok {
		return "", false, false
	}
	return approvalFromAccount(body, c.adminOrg)
}

// iamUserApproved resolves a specific user's approval via IAM get-user (the JWT
// path — the token is validated but its embedded claims may lag a live approval).
// Fail-closed: on any IAM error it returns false (unapproved) rather than allow.
func (c *config) iamUserApproved(r *http.Request, id string) bool {
	if id == "" || id == "/" {
		return false
	}
	u := strings.TrimRight(c.iamInternal, "/") + "/v1/iam/get-user?id=" + url.QueryEscape(id)
	body, ok := c.iamGet(r, u, r.Header.Get("Cookie"))
	if !ok {
		return false
	}
	_, approved, ok := approvalFromAccount(body, c.adminOrg)
	return ok && approved
}

// iamGet performs a server-side GET to IAM, forwarding the caller's cookies. The
// bounded read + timeout mirror the admin-guard get-account call.
func (c *config) iamGet(r *http.Request, urlStr, cookie string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, false
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	return body, true
}

// approvalFromAccount extracts (owner, approved) from an IAM get-account /
// get-user response. The user object is at the top level or under `data`. A user
// is APPROVED unless properties.approvalStatus == "pending" — fail-OPEN so
// existing users (no property) pass — OR the user is an admin (owner==adminOrg or
// isAdmin). An error/unsigned response (status:"error", no owner) → not-ok.
func approvalFromAccount(body []byte, adminOrg string) (owner string, approved bool, ok bool) {
	type acct struct {
		Owner      string            `json:"owner"`
		IsAdmin    bool              `json:"isAdmin"`
		Properties map[string]string `json:"properties"`
	}
	var top struct {
		Status string `json:"status"`
		acct
		Data acct `json:"data"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return "", false, false
	}
	if top.Status == "error" {
		return "", false, false
	}
	a := top.acct
	if a.Owner == "" && top.Data.Owner != "" {
		a = top.Data
	}
	if a.Owner == "" {
		return "", false, false
	}
	// Approval predicate — mirrors object.User.IsApproved (fail-open + admin).
	approved = true
	if a.Owner != adminOrg && !a.IsAdmin {
		if a.Properties != nil && a.Properties["approvalStatus"] == "pending" {
			approved = false
		}
	}
	return a.Owner, approved, true
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

	owner, approved, err := c.exchange(r.Context(), code, verifier, c.callbackURI(r))
	if err != nil {
		log.Printf("waitlist-guard: token exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	// Set a session encoding the approved verdict either way, so the fast path
	// works for approved users AND an unapproved user isn't re-prompted to log in
	// on every request (they get bounced to the waitlist instead).
	c.setSession(w, owner, approved)
	if !approved {
		http.Redirect(w, r, c.waitlistURL, http.StatusFound)
		return
	}
	if returnTo == "" || !strings.HasPrefix(returnTo, "https://") {
		returnTo = "https://console.hanzo.ai"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// exchange swaps the auth code for tokens and resolves (owner, approved) from the
// validated ID/access token claims + an authoritative IAM get-user lookup. Admins
// (owner==adminOrg or isAdmin) are approved without the lookup.
func (c *config) exchange(ctx context.Context, code, verifier, redirectURI string) (string, bool, error) {
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
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, truncate(body, 256))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", false, fmt.Errorf("decode token response: %w", err)
	}

	// Resolve validated claims (owner, name, isAdmin) from the ID or access token.
	var owner, name string
	var isAdmin bool
	for _, t := range []string{tok.IDToken, tok.AccessToken} {
		if t == "" {
			continue
		}
		if claims, verr := c.validator.ValidateRaw(t); verr == nil && claims.Owner != "" {
			owner, name, isAdmin = claims.Owner, claims.Name, claims.IsAdmin
			break
		}
	}
	if owner == "" && tok.AccessToken != "" {
		if o, ok := c.userinfoOwner(ctx, tok.AccessToken); ok {
			owner = o
		}
	}
	if owner == "" {
		return "", false, fmt.Errorf("could not resolve owner from token or userinfo")
	}

	// Admins are always approved. Otherwise resolve the authoritative approval
	// property from IAM get-user (Bearer the freshly-minted access token).
	if owner == c.adminOrg || isAdmin {
		return owner, true, nil
	}
	approved := c.getUserApprovedBearer(ctx, owner+"/"+name, tok.AccessToken)
	return owner, approved, nil
}

// getUserApprovedBearer reads a user's approval from IAM get-user authenticated
// with a Bearer access token. Fail-closed (false) on any error.
func (c *config) getUserApprovedBearer(ctx context.Context, id, accessToken string) bool {
	if id == "" || id == "/" || accessToken == "" {
		return false
	}
	u := strings.TrimRight(c.iamInternal, "/") + "/v1/iam/get-user?id=" + url.QueryEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, approved, ok := approvalFromAccount(body, c.adminOrg)
	return ok && approved
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
	http.Redirect(w, r, c.waitlistURL, http.StatusFound)
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
