// admin-guard is the single forward-auth gate for Hanzo's admin surfaces. It
// authorizes on TWO tiers (one predicate each, both in authz.go's authorize):
//
//  1. GLOBAL platform-sudo — an IAM user whose org (`owner`) is the reserved
//     admin org (owner == AdminOrg) — reaches EVERY admin surface: the raw
//     global/DO-infra consoles (platform.hanzo.ai, studio, commerce-admin, the
//     raw KMS admin UI, the IAM management UI) AND every tenant surface.
//  2. TENANT admin — an owner/admin of a brand org (lux, zoo, hanzo, pars, …) —
//     reaches ONLY that brand's own admin surface (admin.<brand>.<domain>), and
//     is denied on every other brand's surface and on the global surfaces.
//
// The tenant org is derived from the request Host (admin.lux.cloud → lux) — the
// ingress-set X-Forwarded-Host, never user input — against the canonical
// HIP-0111 brand registry mirrored in authz.go. A host that is not a recognized
// tenant surface admits GLOBAL sudo ONLY: fail closed.
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
// order, each producing the SAME principal {owner, isAdmin, orgs} that the ONE
// authorize() predicate consumes:
//
//  1. the guard's own signed session cookie (set after a prior PKCE login) —
//     the browser fast path, carrying owner+isAdmin, scoped to the request's
//     registrable domain;
//  2. a Bearer / Basic JWT validated through the edge (the API path) — carries
//     owner, isAdmin, and the full org-membership set, so no IAM round-trip;
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

	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/gateway/v2/token"
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

	// consoles maps a brand's registrable domain (e.g. "zoo.cloud") to that
	// brand's client console URL. An authenticated non-admin on a guarded host
	// is sent to ITS brand's console (zoo→zoo, lux→lux), never a foreign brand.
	// defaultConsole is the fallback console for an unrecognized host.
	consoles       map[string]string
	defaultConsole string

	// iams maps a brand's registrable domain to that brand's IAM login authority,
	// exactly as consoles does for the console. iamPublic is the fallback for an
	// unrecognized host.
	iams map[string]string

	// The guard session (and PKCE state) cookie is scoped to the REGISTRABLE
	// DOMAIN of each request's host, derived PER REQUEST — a browser can only
	// set a cookie on its own registrable domain, so a single hardcoded
	// ".hanzo.ai" is dropped by admin.zoo.cloud / admin.lux.network. Deriving it
	// per host lets one binary white-label every brand (.hanzo.ai, .zoo.cloud,
	// .lux.network). cookieName/TTL are brand-independent.
	cookieName string
	cookieTTL  time.Duration

	// hmacKey signs the guard session + PKCE state cookies.
	hmacKey []byte

	// validator validates Bearer/Basic JWTs (issuer + audience + expiry) and
	// exposes claims.owner — the same edge validator the gateway uses.
	validator *edge.Verifier
}

// guardVersion is the admin-guard's own semantic version — the ONE canonical
// place it is declared. It is surfaced in the STARTUP LOG so operators can
// confirm which guard build made an authorization decision. Bump the PATCH on
// every behavior change (never a lazy major).
//
// It is deliberately NOT on the health endpoint. /__guard/healthz is
// unauthenticated and reachable on every guarded host, so answering "ok v0.1.9"
// let anyone enumerate which surfaces run which build — the operator question
// ("which guard decided this?") is answered by the log and by the deployment,
// both of which already require access to ask.
const guardVersion = "v0.1.10"

// healthHandler answers the liveness probe and nothing else. The body is a
// constant: a probe reports reachability, and every additional fact on an
// unauthenticated endpoint is a fact an attacker did not have to work for.
func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}
}

const (
	verifyPath = "/__guard/verify"
	// verifyAuthnPath gates a surface on being AUTHENTICATED rather than on
	// being an admin, and writes X-Org-Id so the surface can scope its data to
	// the caller's org. Wire a surface here ONLY once it actually scopes by
	// X-Org-Id — this endpoint grants reach to every authenticated user, and a
	// surface that ignores the header would show all orgs to all of them.
	verifyAuthnPath = "/__guard/verify-authn"
	callbackPath    = "/__guard/callback"
	logoutPath      = "/__guard/logout"
	healthPath      = "/__guard/healthz"

	stateCookie = "hanzo_admin_guard_state"

	// defaultConsoleMap white-labels non-admin bounce targets by brand. One
	// guard binary, every brand — overridable via GUARD_CONSOLES. Keyed by the
	// registrable domain of the guarded host; the value is that brand's console
	// (note: lux's console lives on lux.cloud, not lux.network).
	defaultConsoleMap = "hanzo.ai=https://console.hanzo.ai," +
		"zoo.cloud=https://console.zoo.cloud," +
		"lux.network=https://console.lux.cloud"

	// defaultIAMMap white-labels the LOGIN AUTHORITY by brand, keyed the same way
	// as defaultConsoleMap. Without it every brand's admin surface bounced an
	// anonymous browser to hanzo.id, so admin.lux.network and admin.zoo.cloud
	// rendered "Sign in to Hanzo ID" — Hanzo branding on a Lux/Zoo surface, which
	// the white-label rule forbids outright. The guard already derives the cookie
	// domain, the console and the login org from the request Host; the IAM host is
	// simply the last field that was not. Overridable via GUARD_IAMS.
	defaultIAMMap = "hanzo.ai=https://hanzo.id," +
		"lux.network=https://lux.id," +
		"lux.cloud=https://lux.id," +
		"zoo.cloud=https://zoo.id," +
		"zoo.ngo=https://zoo.id," +
		"zoo.network=https://zoo.id," +
		"pars.ai=https://pars.id," +
		"pars.network=https://pars.id," +
		"bootno.de=https://id.bootno.de"
)

func main() {
	cfg := loadConfig()

	log.Printf("admin-guard: starting %s", guardVersion)

	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, healthHandler())
	mux.HandleFunc(verifyPath, cfg.verifyHandler(adminPolicy))
	mux.HandleFunc(verifyAuthnPath, cfg.verifyHandler(authnPolicy))
	mux.HandleFunc(callbackPath, cfg.handleCallback)
	mux.HandleFunc(logoutPath, cfg.handleLogout)

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Log the per-brand IAM MAP, not just the fallback: printing only iamPublic
	// makes a correctly white-labelled guard look like it still sends every brand
	// to hanzo.id, which reads as the exact bug this map fixes.
	log.Printf("admin-guard %s listening on %s (adminOrg=%q consoles=%v defaultConsole=%s iams=%v iamFallback=%s)",
		guardVersion, cfg.addr, cfg.adminOrg, cfg.consoles, cfg.defaultConsole, cfg.iams, cfg.iamPublic)
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
	// the edge validates against the JWKS issuer; reuse its env (AUTH_ISSUER /
	// AUTH_JWKS_URL) so the guard and gateway agree on the IAM authority.
	vcfg := token.ConfigFromEnv()

	return &config{
		addr:           envOr("GUARD_ADDR", ":8080"),
		iamPublic:      iamPublic,
		iamInternal:    envOr("IAM_INTERNAL_URL", "https://iam.hanzo.ai"),
		clientID:       envOr("IAM_CLIENT_ID", "hanzo-admin-guard"),
		clientSecret:   clientSecret,
		adminOrg:       envOr("IAM_ADMIN_ORG", "admin"),
		consoles:       parseBrandMap(envOr("GUARD_CONSOLES", defaultConsoleMap)),
		defaultConsole: envOr("CONSOLE_URL", "https://console.hanzo.ai"),
		iams:           parseBrandMap(envOr("GUARD_IAMS", defaultIAMMap)),
		cookieName:     envOr("GUARD_COOKIE_NAME", "hanzo_admin_guard"),
		cookieTTL:      envDuration("GUARD_COOKIE_TTL", 8*time.Hour),
		hmacKey:        hmacKey,
		validator:      token.NewValidator(vcfg),
	}
}

// ----------------------------------------------------------------------------
// Forward-auth verdict
// ----------------------------------------------------------------------------

// verifyHandler builds a ForwardAuth target for one policy. Identity resolution
// is IDENTICAL for every policy — same three sources, same order, same
// fail-closed rules — so it lives here once and the policy is the only thing
// that varies. Which handler an ingress middleware points at IS the policy
// choice; nothing in the request can influence it.
func (c *config) verifyHandler(pol policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { c.handleVerify(w, r, pol) }
}

// handleVerify computes the original request URL from the X-Forwarded-* headers
// the ingress sets, resolves the caller's principal, and renders the verdict
// that pol calls for.
func (c *config) handleVerify(w http.ResponseWriter, r *http.Request, pol policy) {
	orig := originalURL(r)

	// (1) Guard session cookie — the browser fast path.
	if p, ok := c.sessionPrincipal(r); ok {
		c.decide(w, r, p, orig, pol)
		return
	}

	// (2) Bearer/Basic JWT — the API path. The JWT carries the full principal
	// (owner, isAdmin, org-membership set) directly.
	if claims, err := c.validator.Verify(r.Header); err == nil && claims != nil {
		c.decide(w, r, principalFromClaims(claims), orig, pol)
		return
	} else if err != nil && err != token.ErrNoToken {
		// A token was presented but did not validate. For an API caller, fail
		// closed with 401 (don't bounce a non-browser through a login redirect).
		if isAPIClient(r) {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		// Browser with a bad/expired bearer — fall through to interactive login.
	}

	// (3) IAM session cookie — resolve via IAM get-account server-side.
	if p, ok := c.iamSessionPrincipal(r); ok {
		c.decide(w, r, p, orig, pol)
		return
	}

	// No identity at all.
	if isAPIClient(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	// Browser → start interactive IAM PKCE login, under THIS surface's policy.
	c.startLogin(w, r, orig, pol)
}

// decide renders the allow/redirect verdict for a resolved principal against the
// surface it is trying to reach, under pol. The host is the ingress-set request
// host — the sole, trusted determinant of the tenant org (see authorize).
func (c *config) decide(w http.ResponseWriter, r *http.Request, p principal, orig string, pol policy) {
	host := requestHost(r)
	if pol.allow(c, p, host) {
		// Allowed. Pass the resolved home org downstream — for an admin grant it
		// is auditing + defense in depth (a global grant carries
		// X-Org-Id==adminOrg, a tenant grant the brand org, so a downstream global
		// surface can still require X-Org-Id==adminOrg). For an AUTHN surface it
		// is load-bearing: X-Org-Id is the ONLY thing scoping what that surface
		// renders, so it must come from the verified `owner` claim and never from
		// the request. Traefik overwrites any client-sent X-Org-Id with this one
		// via the middleware's authResponseHeaders.
		w.Header().Set("X-Org-Id", p.owner)
		// WHO, beside WHICH TENANT. X-Org-Id names the tenant; every member of an
		// org carries the same one, so a surface handed only that header can scope
		// data per tenant and cannot tell two people apart — it has no users. The
		// subject and the address complete the assertion the Hanzo identity-header
		// contract (HIP-0026) already specifies and every in-cluster subsystem
		// already reads, so a gated surface resolves a PERSON without minting a
		// second identity of its own. o11y's iamidentn refuses a request that
		// carries an org and no subject: emitting one without the other is not a
		// partial grant, it is an unusable one.
		//
		// Both are set unconditionally when non-empty and OMITTED at their zero
		// value, mirroring the edge injector: an empty header is indistinguishable
		// from an absent one downstream, and writing "" would only teach Traefik to
		// forward a blank that overwrites nothing.
		if p.uid != "" {
			w.Header().Set("X-User-Id", p.uid)
		}
		if p.email != "" {
			w.Header().Set("X-User-Email", p.email)
		}
		w.Header().Set("X-Admin-Guard", "allow-"+pol.name)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Authenticated, but NOT authorized for THIS surface → THIS brand's client
	// surface (zoo→zoo console, lux→lux console), never a foreign brand's console.
	if isAPIClient(r) {
		http.Error(w, pol.denial, http.StatusForbidden)
		return
	}
	http.Redirect(w, r, c.consoleFor(host), http.StatusFound)
}

// ----------------------------------------------------------------------------
// Identity source (1): the guard's own signed session cookie
// ----------------------------------------------------------------------------

// sessionFields is the EXACT arity of the session cookie payload:
// owner|isAdmin|expiryUnix|uid|email. The cookie is the browser fast path, and
// it must reproduce the whole principal the login resolved — a cookie that
// carried only the tenant made every request after the first one anonymous as to
// WHO, so a gated surface saw a person on the login round-trip and a bare org
// forever after. Nothing here is optional: email may be empty, but its FIELD is
// always present, because a variable-arity payload cannot be parsed unambiguously
// once a value may itself be empty.
const sessionFields = 5

// sessionPrincipal returns the principal from a valid, unexpired guard session
// cookie. Cookie value: base64(owner|isAdmin|expiryUnix|uid|email) "." base64(HMAC),
// where isAdmin is the bit "1"/"0". Tamper-evident (HMAC) and time-bounded; no
// server-side store. A cookie that is not EXACTLY the canonical five-field form
// (e.g. a pre-v0.1.9 three-field cookie, or a truncated/garbage one) is rejected —
// fail closed, the holder re-authenticates. The membership set is not carried in
// the cookie, so the cookie path authorizes a HOME-org admin only.
func (c *config) sessionPrincipal(r *http.Request) (principal, bool) {
	ck, err := r.Cookie(c.cookieName)
	if err != nil {
		return principal{}, false
	}
	payload, ok := c.verifySigned(ck.Value)
	if !ok {
		return principal{}, false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != sessionFields {
		return principal{}, false
	}
	owner := parts[0]
	if owner == "" {
		return principal{}, false
	}
	expUnix, err := parseInt(parts[2])
	if err != nil || time.Now().Unix() > expUnix {
		return principal{}, false
	}
	return principal{owner: owner, isAdmin: parts[1] == "1", uid: parts[3], email: parts[4]}, true
}

// sessionBit renders the isAdmin flag for the session cookie payload.
func sessionBit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// sessionPayload renders a principal into the canonical session-cookie payload
// sessionPrincipal parses. ONE renderer facing ONE parser: the format was
// written in setSession and read in sessionPrincipal, and every caller that
// needed a cookie (tests included) hand-rolled the format a third time — which
// is how a field can be added to the writer and silently not to the readers.
func sessionPayload(p principal, exp time.Time) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s", p.owner, sessionBit(p.isAdmin), exp.Unix(), p.uid, p.email)
}

func (c *config) setSession(w http.ResponseWriter, r *http.Request, p principal) {
	exp := time.Now().Add(c.cookieTTL)
	payload := sessionPayload(p, exp)
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    c.sign(payload),
		Path:     "/",
		Domain:   registrableDomain(requestHost(r)),
		Expires:  exp,
		MaxAge:   int(c.cookieTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *config) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   registrableDomain(requestHost(r)),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ----------------------------------------------------------------------------
// Identity source (3): IAM session cookie → get-account
// ----------------------------------------------------------------------------

const (
	// iamLookupTimeout caps one pre-auth IAM get-account. It is an in-cluster
	// call; 2s is already far beyond its normal latency, and the number that
	// matters is how long an ANONYMOUS request can hold a guard goroutine.
	iamLookupTimeout = 2 * time.Second

	// maxIAMLookupTimeout is the ceiling the test holds this to, so raising the
	// timeout is a deliberate act with a reason next to it rather than a drift.
	maxIAMLookupTimeout = 3 * time.Second

	// iamLookupInFlight bounds concurrent pre-auth IAM round-trips. Sized well
	// above real login concurrency for a guarded admin surface and far below what
	// it takes to exhaust the guard or to matter to IAM.
	iamLookupInFlight = 32
)

// iamGate bounds the pre-auth IAM round-trips in flight across the process.
var iamGate = newInFlightGate(iamLookupInFlight)

// inFlightGate admits up to n concurrent holders and refuses the rest. A
// buffered channel is the whole implementation: enter takes a slot or reports
// that there is none, and never blocks — a pre-auth path that QUEUED would trade
// a bounded goroutine count for an unbounded wait, which is the same denial
// wearing a different number.
type inFlightGate struct{ slots chan struct{} }

func newInFlightGate(n int) *inFlightGate {
	return &inFlightGate{slots: make(chan struct{}, n)}
}

func (g *inFlightGate) enter() bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *inFlightGate) leave() { <-g.slots }

// iamSessionPrincipal forwards the inbound cookies to IAM get-account and reads
// the authenticated user's principal (owner + isAdmin). This covers a browser
// that holds an IAM SSO session but has not yet been issued a guard cookie. The
// membership set is not read here, so this path authorizes a HOME-org admin only.
func (c *config) iamSessionPrincipal(r *http.Request) (principal, bool) {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return principal{}, false
	}

	// THIS IS THE PRE-AUTH PATH, so the work an anonymous caller can compel here
	// is the guard's exposure. Any non-empty Cookie reaches it — the guard cannot
	// tell IAM's session cookie from a random one without knowing IAM's cookie
	// name, and hardcoding that name would break the SSO fast path the day IAM
	// renamed it. So bound the COST rather than guess at the input: at most
	// iamLookupInFlight of these run at once, and each is capped at
	// iamLookupTimeout. Beyond the bound the guard declines to make the call and
	// falls through to interactive login, which is where an anonymous browser was
	// going anyway.
	//
	// It used to be an 8s timeout with no bound, so a volume of anonymous requests
	// carrying any cookie could hold a goroutine and an IAM connection each, for
	// eight seconds each, and load IAM's get-account 1:1 while doing it.
	if !iamGate.enter() {
		return principal{}, false
	}
	defer iamGate.leave()

	ctx, cancel := context.WithTimeout(r.Context(), iamLookupTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.iamInternal, "/")+"/v1/iam/get-account", nil)
	if err != nil {
		return principal{}, false
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return principal{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return principal{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return principal{}, false
	}
	return principalFromAccount(body)
}

// principalFromAccount extracts the user's principal (org + org-admin bit) from
// an IAM get-account response. IAM get-account returns the User object
// either at the top level or wrapped under `data`; the org slug is `owner` and
// the org-admin flag is `isAdmin`. An error/unsigned response has status:"error"
// and no owner → not a principal (fail closed).
func principalFromAccount(body []byte) (principal, bool) {
	// account is the User shape at either position; declared once so the two
	// positions cannot drift apart as fields are added.
	type account struct {
		Owner   string `json:"owner"`
		IsAdmin bool   `json:"isAdmin"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}
	var top struct {
		Status string `json:"status"`
		account
		Data account `json:"data"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return principal{}, false
	}
	if top.Status == "error" {
		return principal{}, false
	}
	a := top.account
	if a.Owner == "" {
		a = top.Data
	}
	if a.Owner == "" {
		return principal{}, false
	}
	// `id` is IAM's own subject; `name` is the username IAM mints `sub` from when
	// the account response predates ids. Same precedence as the JWT path's
	// UserID(), so all three sources name the same person the same way.
	return principal{owner: a.Owner, isAdmin: a.IsAdmin, uid: firstNonEmpty(a.ID, a.Name), email: a.Email}, true
}

// ----------------------------------------------------------------------------
// OAuth2 Authorization-Code + PKCE login
// ----------------------------------------------------------------------------

// startLogin redirects the browser to IAM's authorize endpoint with a PKCE
// challenge, stashing the verifier, the post-login return URL and the POLICY of
// the surface that started the login in a short-lived signed state cookie.
func (c *config) startLogin(w http.ResponseWriter, r *http.Request, returnTo string, pol policy) {
	verifier := randString(48)
	challenge := pkceChallenge(verifier)
	nonce := randString(16)

	// state cookie payload: nonce|verifier|returnTo|policy (signed, 10-minute life).
	// The POLICY rides here because the callback is ONE path shared by every
	// guarded surface — the ingress picks the policy by choosing a verify endpoint,
	// and /__guard/callback has no such choice to read. It is inside the HMAC, so
	// it is a fact the guard told itself, not a parameter the browser can set.
	statePayload := strings.Join([]string{nonce, verifier, returnTo, pol.name}, "\x1f")
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    c.sign(statePayload),
		Path:     "/",
		Domain:   registrableDomain(requestHost(r)),
		MaxAge:   600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	q := url.Values{}
	q.Set("client_id", c.clientID)
	// Pin the login org to the surface being guarded (see loginOrg): a tenant
	// surface (admin.lux.cloud) authenticates the user into that tenant org (lux)
	// so a tenant admin can log in; the global/DO-infra surfaces + unknown hosts
	// pin the reserved admin org, preserving the global-admin login there. This
	// only steers the login; handleCallback re-runs authorize() before minting a
	// session, so an unexpected resolved org is denied, never trusted.
	q.Set("organization", c.loginOrg(requestHost(r)))
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", c.callbackURI(r))
	q.Set("state", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	authorize := strings.TrimRight(c.iamFor(requestHost(r)), "/") + "/v1/iam/oauth/authorize?" + q.Encode()
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
	parts := strings.SplitN(payload, "\x1f", stateFields)
	if len(parts) != stateFields || subtleNE(parts[0], gotState) {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	verifier, returnTo, pol := parts[1], parts[2], policyByName(parts[3])
	// Clear the state cookie (same registrable domain it was set on).
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", Domain: registrableDomain(requestHost(r)), MaxAge: -1, Secure: true, HttpOnly: true})

	p, err := c.exchange(r.Context(), code, verifier, c.callbackURI(r))
	if err != nil {
		log.Printf("admin-guard: token exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	// Re-run the SAME predicate the forward-auth path will apply — THIS surface's
	// policy, recovered from the signed state, not the admin policy for everyone.
	// Only a principal that policy admits gets a session cookie; an
	// authenticated-but-unauthorized login is bounced to the brand console with NO
	// session minted — fail closed, no wrongful grant.
	//
	// It used to be authorize() unconditionally, which is the ADMIN policy. That
	// made an authn surface unreachable for exactly the people it exists for: a
	// non-admin passed IAM, came back here, failed the admin test, and was
	// redirected to the console with no session — so the next request started the
	// same loop. The gate said "anyone authenticated" and the login said "admins
	// only"; two predicates for one decision is the shape of a lockout.
	if !pol.allow(c, p, requestHost(r)) {
		http.Redirect(w, r, c.consoleFor(requestHost(r)), http.StatusFound)
		return
	}
	c.setSession(w, r, p)
	if !c.returnToAllowed(r, returnTo) {
		returnTo = c.consoleFor(requestHost(r))
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// returnToAllowed reports whether the post-login destination is a place this
// guard is willing to send a browser: an absolute https URL on the HOST BEING
// GUARDED, and nowhere else.
//
// The old test was HasPrefix(returnTo, "https://"), which constrains the SCHEME
// and says nothing about the destination. It held only because returnTo is built
// from X-Forwarded-Host and travels inside the HMAC-signed state — so the guard
// was trusting a header to decide where a freshly authenticated browser lands.
// That is one misconfigured hop (a route that forwards a client's own
// X-Forwarded-Host) away from handing a logged-in user to another origin, and
// the guard can settle it locally instead: it already knows which host it is
// guarding, because that is what it just authenticated FOR.
//
// url.Parse rather than string surgery, because every classic bypass of this
// check is a string that a prefix test reads differently from a URL parser —
// https://guarded.example.evil/, https://evil/@guarded.example/, a
// scheme-relative //evil/, a backslash where a parser expects a slash. Comparing
// the parsed Host to the guarded host answers all of them the same way.
func (c *config) returnToAllowed(r *http.Request, returnTo string) bool {
	if returnTo == "" {
		return false
	}
	u, err := url.Parse(returnTo)
	if err != nil || u.Scheme != "https" {
		return false
	}
	return hostOnly(u.Host) == requestHost(r)
}

// exchange swaps the auth code for tokens and resolves the principal from the ID
// token (validated via the edge) or, failing that, the userinfo endpoint.
func (c *config) exchange(ctx context.Context, code, verifier, redirectURI string) (principal, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code_verifier", verifier)

	tokenURL := strings.TrimRight(c.iamInternal, "/") + "/v1/iam/oauth/token"
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return principal{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return principal{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return principal{}, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, truncate(body, 256))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return principal{}, fmt.Errorf("decode token response: %w", err)
	}

	// Prefer the ID token's validated claims (owner, isAdmin, membership set).
	if tok.IDToken != "" {
		if claims, verr := c.validator.VerifyRaw(tok.IDToken); verr == nil && claims.Owner != "" {
			return principalFromClaims(claims), nil
		}
	}
	if tok.AccessToken != "" {
		if claims, verr := c.validator.VerifyRaw(tok.AccessToken); verr == nil && claims.Owner != "" {
			return principalFromClaims(claims), nil
		}
	}
	// Fallback: call userinfo with the access token.
	if tok.AccessToken != "" {
		if p, ok := c.userinfoPrincipal(ctx, tok.AccessToken); ok {
			return p, nil
		}
	}
	return principal{}, fmt.Errorf("could not resolve owner from token or userinfo")
}

func (c *config) userinfoPrincipal(ctx context.Context, accessToken string) (principal, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.iamInternal, "/")+"/v1/iam/oauth/userinfo", nil)
	if err != nil {
		return principal{}, false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return principal{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return principal{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ui struct {
		Owner             string `json:"owner"`
		IsAdmin           bool   `json:"isAdmin"`
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(body, &ui); err != nil {
		return principal{}, false
	}
	// OIDC userinfo names the subject `sub`. Same precedence as the JWT and
	// get-account paths, so all three sources resolve one person to one uid.
	return principal{owner: ui.Owner, isAdmin: ui.IsAdmin, uid: firstNonEmpty(ui.Sub, ui.PreferredUsername), email: ui.Email}, ui.Owner != ""
}

func (c *config) handleLogout(w http.ResponseWriter, r *http.Request) {
	c.clearSession(w, r)
	http.Redirect(w, r, c.consoleFor(requestHost(r)), http.StatusFound)
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
	return proto + "://" + requestHost(r) + callbackPath
}

// requestHost is the browser-facing host being guarded. The ingress sets
// X-Forwarded-Host on the forward-auth subrequest; the guard's own callback +
// login endpoints are served through the same per-host ingress route (so
// r.Host agrees). Port is stripped so cookie-domain derivation is exact.
func requestHost(r *http.Request) string {
	return hostOnly(firstNonEmpty(r.Header.Get("X-Forwarded-Host"), r.Host))
}

// hostOnly strips any :port and trailing dot from a host[:port].
func hostOnly(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}

// registrableDomain returns the cookie scope for a host: the last two dot-labels
// with a leading dot (".hanzo.ai" for "admin.hanzo.ai", ".zoo.cloud" for
// "admin.zoo.cloud"). A browser only accepts a Set-Cookie whose Domain is the
// registrable domain of the host it is on, so the guard MUST derive this per
// request rather than pin one ".hanzo.ai" — that pin is silently dropped on
// admin.zoo.cloud / admin.lux.network, breaking the login (no session sticks).
// Returns "" (host-only cookie) for a single-label host such as localhost.
func registrableDomain(host string) string {
	host = hostOnly(host)
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	return "." + strings.Join(labels[len(labels)-2:], ".")
}

// consoleFor returns the brand console URL for a request host (zoo→zoo console,
// lux→lux console), defaulting to the primary console for an unrecognized host.
func (c *config) consoleFor(host string) string {
	reg := strings.TrimPrefix(registrableDomain(host), ".")
	if u, ok := c.consoles[reg]; ok && u != "" {
		return u
	}
	return c.defaultConsole
}

// iamFor returns the login authority for the brand of host, so a Lux/Zoo/Pars
// surface authenticates against ITS OWN IAM and never renders Hanzo branding.
func (c *config) iamFor(host string) string {
	reg := strings.TrimPrefix(registrableDomain(host), ".")
	if u, ok := c.iams[reg]; ok && u != "" {
		return u
	}
	return c.iamPublic
}

// parseBrandMap parses a "domain=url,domain=url" list into a brand→URL map —
// ONE parser for every brand-keyed table (consoles, iams). Malformed pairs are
// skipped; the result is never nil.
func parseBrandMap(s string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); k != "" {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// isAPIClient reports whether the caller looks like a non-browser API client
// (so we fail closed with a status code instead of an interactive redirect).
func isAPIClient(r *http.Request) bool {
	if edge.Bearer(r.Header) != "" || edge.Basic(r.Header) != "" {
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
