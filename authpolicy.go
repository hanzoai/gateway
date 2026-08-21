// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// authpolicy.go is the gateway's HTTP authn policy, stated ONCE.
//
// The policy is a decision about a request — its method, its host, its path and
// its headers — and it is the same decision whichever HTTP framework carries
// the request. It used to be written inside a gin closure, which braided the
// decision together with the framework that happened to be running it, and the
// cost of that braiding was a second copy: the HIP-0106 mount could not run the
// gin middleware natively, so it bridged through a whole gin engine per request
// to reach a rule that never needed gin at all.
//
// Now the rule is a value — [authGate] — and each transport is a dozen lines of
// adapter over it:
//
//	auth_middleware.go   gin, for the legacy Lura edge (the shipping image)
//	mount.go             native zip, for the HIP-0106 unified cloud binary
//	handler_factory.go   the endpoint pipeline's requirement — [AuthConfig.require]
//
// (The ZAP relay's envelope gate in gate.go states the same ALLOW/DENY ladder
// against forward.Forward, which carries identity as fields rather than as
// headers and is billed by cloud rather than here. It is listed as the third
// transport in that file's header; folding it in here would require a header
// view over the envelope and would give the relay a per-request Commerce
// round-trip it deliberately does not have — see HIP-0110.)
//
// What "one place" buys, concretely: the identity strip is now the FIRST thing
// every HTTP transport does, and it now actually survives. Through the old gin
// bridge it did not — the net/http→fasthttp adapter copies the middleware's
// headers back onto the request with Set and never Del, so a header the strip
// DELETED stayed on the request the downstream read. A client-supplied
// X-User-IsAdmin survived the trust boundary. See TestMountAuth_StripSurvives.
package gateway

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
)

// authEnabled reports whether the edge enforces this policy, from AUTH_ENABLED.
//
// One reader, for every transport. The switch has exactly one off position:
// the policy is enforced unless AUTH_ENABLED says "false", so a value that says
// neither — "0", "no", "off", a typo, a stray space — leaves it in force. Case
// and surrounding space are trimmed, because "False" from a chart value and
// "false" from a ConfigMap are the same intent and should not be two answers.
//
// Two transports reading this differently is two policies: whichever reader is
// looser decides, and it decides on a string nobody looked at twice.
func authEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_ENABLED")), "false")
}

// refusal is a gate decision to STOP the request: the status to answer with and
// the JSON body to answer it with. nil means allow.
//
// It is data rather than a write to a ResponseWriter because the gate does not
// know what it is writing to — gin aborts with its own JSON, zip answers with
// c.JSON, and a third transport would do a third thing. Deciding and answering
// are separate concerns, and only the answering part is framework-shaped.
type refusal struct {
	Status int
	Body   map[string]string
}

// authGate is the compiled policy: the config plus the things built once from
// it (the JWKS-backed verifier, the Commerce balance client, the public-host
// set). Build it once per transport with [newAuthGate] and call [authGate.admit]
// per request.
type authGate struct {
	cfg           AuthConfig
	validator     *edge.Verifier
	billing       *billingChecker
	publicHosts   map[string]bool
	misconfigured bool
}

// newAuthGate compiles cfg into the gate. The verifier's JWKS cache is
// constructed here and reused for every request the returned gate admits, so
// signing keys are fetched once per gate and TTL-refreshed thereafter.
func newAuthGate(cfg AuthConfig) *authGate {
	g := &authGate{cfg: cfg}
	if !cfg.Enabled {
		return g
	}
	g.validator = newValidator(cfg)
	g.billing = newBillingChecker(cfg.BillingURL, cfg.BillingToken)

	// Fail-secure: billing enabled but its Commerce dependency is not fully
	// configured. gateway.Mount refuses to start in this state (cfg.Validate);
	// this covers the standalone path, which has no error return — the balance
	// gate denies the metered surface (503) instead of failing open. The funding
	// surface stays reachable (billingPathMatch excludes /v1/commerce).
	g.misconfigured = cfg.BillingEnabled && (cfg.BillingURL == "" || cfg.BillingToken == "")
	if g.misconfigured {
		log.Printf("gateway auth: BILLING_ENABLED=true but AUTH_BILLING_URL or COMMERCE_SERVICE_TOKEN is empty; metered surface fails closed (503) until both are set from KMS")
	}

	g.publicHosts = make(map[string]bool, len(cfg.PublicHosts))
	for _, h := range cfg.PublicHosts {
		g.publicHosts[h] = true
	}
	return g
}

// admit runs the whole policy against one request and reports whether to carry
// it. h is the request's MUTABLE header set: admit deletes through it what the
// client claimed and writes through it what the token proved, so the caller has
// nothing to copy back and no ordering to remember.
//
// host may carry a port; admit strips it, so every transport hands over
// whatever its framework calls the host and they agree.
//
// Returns nil to allow. A non-nil *refusal is a policy rejection with the
// status and body to answer — never an error, because a rejected request is a
// normal HTTP outcome and not a failure of the gate.
func (g *authGate) admit(method, host, path string, h Headers) *refusal {
	// SECURITY: unconditionally strip client-supplied identity headers. Only the
	// gateway is authorized to set these, and only after JWT validation. This
	// MUST be the first action, before any route-class dispatch.
	//
	// GLOBAL IDENTITY INVARIANT — applies to EVERY class, unconditionally:
	// identity headers are gateway-WRITTEN, never client-accepted. Load-bearing,
	// NOT a bypass-afterthought:
	//   • Authed class writes X-User-Id / X-Org-Id / X-User-Email unconditionally,
	//     but X-Project-Id, X-Billing-Account-Id, X-Roles, X-Phone-Number,
	//     X-User-IsAdmin, X-User-Permissions are written ONLY when the validated
	//     JWT asserts them — a forged copy of any of THOSE would otherwise survive
	//     un-overwritten below → privilege / tenant spoof. (Legacy
	//     X-User-IsGlobalAdmin is NEVER written now — platform sudo is
	//     org=="admin" — but stays in the strip set so a forged copy is dropped.)
	//   • Ingest class (class 1) writes NOTHING, so this guarantees no client
	//     identity ever reaches cloud, which resolves the org solely from the DSN.
	// ONE strip at ingress (never scattered per-header Dels) IS the whole invariant.
	//
	// The strip RETURNS the org the client selected (the inbound X-Org-Id) as it
	// deletes it — the one identity value that survives, and only as an INTENT. It
	// is used solely below, after JWT validation, where EffectiveOrg checks it
	// against the token's signed membership set before any of it is rewritten. On
	// every class that writes nothing (ingest, public host, public path, tokenless,
	// API key) it is simply discarded, so those paths are untouched.
	selectedOrg := stripClaimed(h)

	// When auth is disabled (AUTH_ENABLED=false) the strip above still ran:
	// even in dev/test a downstream must not trust client-supplied identity.
	// Nothing else applies — no token validation, no balance gate.
	if !g.cfg.Enabled {
		return nil
	}

	host = hostOnly(host)

	// ── ROUTE CLASS 1 — tokenless DSN ingest (orthogonal to the authed API) ──
	// POST /v1/sentinel/<project>/{envelope,store}[/] and the o11y errortracking
	// wire POST /v1/o11y/api/<project>/{envelope,store}[/]. A first-class ROUTING
	// decision, NOT a hole punched in the authed gate: this class has its own
	// (empty) auth — forward to cloud with NO IAM-JWT gate and NO written
	// identity; cloud DSN-authenticates and derives the org FROM the DSN.
	// isIngestPath is POST-only + suffix-anchored, so every Sentry/o11y READ falls
	// through to the authed class below and stays JWT-gated.
	if isIngestPath(method, path) {
		return nil
	}

	// ── ROUTE CLASS 2 — authed API (every other /v1/*) ──────────────────────
	// Its own auth chain, below: no-auth allowlist (public IAM/login hosts +
	// public paths) → IAM-JWT validate (401 if absent-and-required, or invalid) →
	// WRITE the canonical identity headers FROM the validated JWT (overwriting the
	// stripped slate) → balance gate. On this class the gateway is the SOLE source
	// of identity; a client-supplied value can never reach a backend.

	// Skip auth for public hosts (IAM/login domains).
	if g.publicHosts[host] {
		return nil
	}

	// Skip auth for public paths.
	for _, pp := range g.cfg.PublicPaths {
		if strings.HasPrefix(path, pp) {
			return nil
		}
	}

	// Extract the credential from the Authorization header or the session cookie.
	tok := edge.Bearer(h)
	if tok == "" {
		tok = edge.Cookie(h)
	}

	if tok == "" {
		if g.cfg.RequireAuth {
			return unauthorized()
		}
		// No token: pass through with no identity headers.
		return nil
	}

	// API keys (sk-*, pk-*, fw_*, hz_*, and retired hk-*) are validated by the backend
	// services directly (cloud, commerce, …), not by the gateway. Pass them
	// through without JWT validation.
	if authz.IsAPIKey(tok) {
		return nil
	}

	claims, err := g.validator.VerifyRaw(tok)
	if err != nil {
		return &refusal{Status: http.StatusUnauthorized, Body: map[string]string{
			"error":   "unauthorized",
			"message": "Invalid token",
			"detail":  err.Error(),
		}}
	}

	// The org that PAYS. It is a SEPARATE question from the org the request ACTS
	// in (which writeIdentity resolves and writes): an operator viewing a customer
	// reads the customer's data and spends the ADMIN ledger, never the customer's.
	ledgerOrg := claims.LedgerOrg(selectedOrg)
	userID := claims.UserID()

	// ONE write, from the one place that decides it (identity.go → hanzoai/authz/edge).
	writeIdentity(h, claims, selectedOrg)

	return g.balance(path, ledgerOrg, userID)
}

// balance is the path-scoped, fail-closed balance gate — the last step of the
// authed class, split out because it is the only step that talks to another
// service and the only one a transport may want to reason about on its own.
//
// Scope: cfg.BillingPaths (the metered must-gate surface — cloud, tasks,
// insights, o11y, mpc, evals, licensing, product, provisioning, …). The
// /v1/commerce funding surface is hard-excluded (billingPathMatch) so a
// zero-balance user can always reach it to add funds. The AI routes bill
// per-token downstream and the validated/public routes are never balance-gated,
// so they are NOT in BillingPaths and skip this gate. Empty BillingPaths
// enforces on every non-funding, non-public route.
//
// Key: the IAM "org/sub" composite — org from claims.LedgerOrg (the org that
// PAYS, not necessarily the one the request acts in), sub from the user.
// Commerce's /v1/billing/balance is user-scoped under an org (the verified
// contract); per-org billing would require a commerce-side balance-model change
// first, so the org is carried in the key rather than used alone.
func (g *authGate) balance(path, ledgerOrg, userID string) *refusal {
	if !g.cfg.BillingEnabled || userID == "" || !billingPathMatch(path, g.cfg.BillingPaths) {
		return nil
	}
	// Fail closed when billing is enabled but misconfigured (no URL or token) —
	// never serve metered product we cannot bill for.
	if g.misconfigured {
		return unavailable()
	}

	// Construct the Commerce user identifier: org/username.
	billingUser := userID
	if ledgerOrg != "" && !strings.Contains(userID, "/") {
		billingUser = ledgerOrg + "/" + userID
	}

	hasBalance, err := g.billing.checkBalance(billingUser)
	switch {
	case hasBalance:
		return nil
	case err != nil:
		// Could not verify balance. Deny (no free), but signal an outage rather
		// than wrongly telling a paying user they are out of funds.
		return unavailable()
	default:
		return &refusal{Status: http.StatusPaymentRequired, Body: map[string]string{
			"error":   "insufficient_balance",
			"message": "Your account has insufficient balance. Please add funds at the platform billing page",
			"user":    billingUser,
		}}
	}
}

// require is the endpoint half of the same policy: [authGate.admit] VERIFIES a
// credential, require states that a particular route NEEDS one.
//
// It performs no cryptography. It opens no JWKS, parses no token and knows no
// signing algorithm — it reads the identity admit already proved and wrote, and
// refuses when there is none. That is the whole of the fix for the double
// validation: the endpoint pipeline used to answer "does this route need a
// token?" by validating the token a second time, with a second library, against
// a second key source. Now it reads the first answer.
//
// A request carrying an API key (hk-, sk-, …) reaches here with no identity by
// design — admit passes those to the backend that owns them — so a route that
// needs an IAM identity refuses it, which is what the endpoint validators did.
//
// AUTH_ENABLED=false means no auth: the strip still runs, nothing is required.
func (c AuthConfig) require(h edge.Headers) *refusal {
	if !c.Enabled || h.Get(authz.HeaderUser) != "" {
		return nil
	}
	return unauthorized()
}

// unauthorized is the answer to a request that brought no usable credential,
// written once so the token-required refusal and the endpoint-required refusal
// are the same answer rather than two that drifted.
func unauthorized() *refusal {
	return &refusal{Status: http.StatusUnauthorized, Body: map[string]string{
		"error":   "unauthorized",
		"message": "Authentication required",
	}}
}

// unavailable is the balance gate's outage answer, written once because it is
// returned from two places that must not drift into two different messages.
func unavailable() *refusal {
	return &refusal{Status: http.StatusServiceUnavailable, Body: map[string]string{
		"error":   "billing_unavailable",
		"message": "Billing is temporarily unavailable. Please retry shortly.",
	}}
}

// hostOnly drops the port from a Host header value. Every transport spells the
// host differently (gin hands over r.Host, fasthttp its own), so the trimming
// happens once here rather than at each call site — where one of them would
// eventually forget and a public host would stop matching on a non-default port.
func hostOnly(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

// ─── What the CONFIG states ─────────────────────────────────────────────────
//
// The request half above answers "does this credential pass?". This half
// answers "does this route need one?", and it is answered by the service
// config rather than by code, because the answer differs per endpoint and per
// estate. Both halves live here so the two cannot drift into two policies.

// authPublic is the endpoint key that says a route is reachable without a
// credential — the AI surface (which carries an API key the backend owns),
// the health probes and the public catalogs.
//
// It is a DECLARATION, not a module: the endpoint pipeline runs no JWT
// validator of its own. The one validator is the trust boundary the engine
// installs ahead of routing, which verifies the IAM token against hanzo.id
// over TLS, enforces the issuer and the audience allowlist, strips what the
// client claimed and writes what the token proved. This key only says whether
// THIS route needs that to have happened.
//
// The polarity is deliberate: absent means REQUIRED. An endpoint added to the
// config without thinking about auth is gated, not open.
const authPublic = "auth/public"

// authNamespace prefixes every key an endpoint may use to state something
// about credentials — authPublic, and the credential modules the schema still
// admits (auth/client-credentials, auth/revoker).
const authNamespace = "auth/"

// public reports whether cfg declares the endpoint reachable without a
// credential. Anything but an explicit `true` is a gated route.
func public(cfg *config.EndpointConfig) bool {
	open, _ := cfg.ExtraConfig[authPublic].(bool)
	return open
}

// policy is what a service config STATES about credentials, counted over its
// endpoints.
type policy struct {
	routes int // endpoints the config declares
	open   int // endpoints declared reachable without a credential
	gated  int // endpoints that state a credential requirement
}

// readPolicy counts what cfg states. An endpoint states something when it
// carries any key in the auth namespace: `auth/public: true` opens it, and
// `auth/public: false` — like every other auth key — states a requirement.
func readPolicy(cfg config.ServiceConfig) policy {
	p := policy{routes: len(cfg.Endpoints)}
	for _, e := range cfg.Endpoints {
		switch {
		case public(e):
			p.open++
		case stated(e):
			p.gated++
		}
	}
	return p
}

// stated reports whether the endpoint declares anything in the auth namespace.
func stated(e *config.EndpointConfig) bool {
	for k := range e.ExtraConfig {
		if strings.HasPrefix(k, authNamespace) {
			return true
		}
	}
	return false
}

// check reports whether this config is one the binary can serve.
//
// A route requires an IAM identity unless it declares authPublic, so the config
// is where the open surface is NAMED — and the requirement is that EVERY route
// says which it is. Not "somewhere in this file the word appears": a config
// written against the older contract states a requirement on the routes it
// gated and says nothing on the routes it left open, which reads as a config
// that made a decision while every one of those open routes now demands an
// identity nothing sends.
//
// Boot is the only place that difference is observable: the probes are a
// process check and read no endpoint, so a process that starts reports healthy
// whatever this config says, and the routes that stopped answering are the ones
// nobody was authenticating to. So the answer is to not start.
//
// A config with no endpoints passes — there is no surface to state a policy
// about, and 0 == 0+0.
func (p policy) check() error {
	if p.routes == p.open+p.gated {
		return nil
	}
	return fmt.Errorf("%d of %d endpoints state no credential policy: every route says whether it "+
		"needs an IAM identity, with %q true or false, and this config leaves that unsaid on %d of "+
		"them. Classify them in the mounted config, then start",
		p.routes-p.open-p.gated, p.routes, authPublic, p.routes-p.open-p.gated)
}
