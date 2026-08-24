// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/hanzoai/authz"
)

// authz.go is the guard's AUTHORIZATION CORE — the one place that answers "may
// this principal reach the admin surface on this host?". It is deliberately
// isolated from the HTTP/OAuth mechanics in main.go so it can be read and
// attacked as a unit: pure predicates over a resolved principal + a request
// host, no I/O, no request parsing. Every identity source in main.go collapses
// to a principal and calls authorize(); nothing else makes an allow decision.

// principal is the resolved, TRUSTED identity the guard authorizes. It is the
// SAME shape regardless of source (guard session cookie, Bearer/Basic JWT, IAM
// the account read), so authorization is a pure function of a principal + a host.
//
//   - owner   : the subject's HOME org slug (IAM `owner`) — identity anchor.
//   - isAdmin : the subject is an org-level admin/owner of its HOME org
//     (IAM `isAdmin`). This is NEVER the platform-sudo bit (that is owner ==
//     adminOrg); it is the per-org owner flag, so it authorizes ONLY the home
//     org's own tenant surface.
//   - orgs    : the full org-membership set with per-org roles. Populated ONLY on
//     the JWT path (the token carries it); nil on the cookie / account paths,
//     which therefore authorize a HOME-org admin only. Fail-closed: a nil set
//     never widens access, it only ever fails to recognize a non-home admin.
//   - uid     : WHO, as opposed to WHICH TENANT — the IAM subject (`sub`). It
//     authorizes nothing; it is what a gated surface keys the PERSON on. owner
//     alone cannot: every member of an org shares it, so a surface given only
//     X-Org-Id can tell tenants apart and not people. A surface that stores
//     per-user rows (a dashboard's author, a saved view, a preference) needs
//     this or it cannot have users at all.
//   - email   : the person's address, for attribution and display. Descriptive,
//     never load-bearing for a decision here.
type principal struct {
	owner   string
	isAdmin bool
	orgs    []authz.Membership
	uid     string
	email   string
}

// principalFromClaims lifts a validated JWT into a principal. The claims are
// IAM-signed (issuer + audience + expiry enforced by the edge), so owner,
// isAdmin, the membership set, the subject and the email are trusted, not
// client-forgeable.
func principalFromClaims(c *authz.Claims) principal {
	return principal{owner: c.Owner, isAdmin: c.IsAdmin, orgs: c.Orgs, uid: c.UserID(), email: c.Email}
}

// adminOf reports whether the principal holds an owner/admin role in org. Two
// independent, trusted signals satisfy it, mirroring the edge's model:
//
//   - the org IS the subject's home org AND it is a home-org admin (isAdmin), or
//   - the subject carries an explicit membership in org with role owner|admin.
//
// A plain `member` role never satisfies it — so a regular member of the lux org
// is NOT a lux tenant admin. Comparison is case- and space-insensitive to match
// the edge (org slug casing is not guaranteed); an empty org is never an admin
// target.
func (p principal) adminOf(org string) bool {
	org = strings.TrimSpace(org)
	if org == "" {
		return false
	}
	if p.isAdmin && strings.EqualFold(strings.TrimSpace(p.owner), org) {
		return true
	}
	for _, m := range p.orgs {
		if !strings.EqualFold(strings.TrimSpace(m.Org), org) {
			continue
		}
		role := strings.TrimSpace(string(m.Role))
		if strings.EqualFold(role, "owner") || strings.EqualFold(role, "admin") {
			return true
		}
	}
	return false
}

// isPlatformSudo reports whether owner is the reserved global-admin org
// (owner == adminOrg). This is the ONE platform-sudo predicate, byte-for-byte
// the same meaning authz.Claims.PlatformSudo enforces on the other side of the trust
// boundary. A platform-sudo principal reaches EVERY admin surface.
func (c *config) isPlatformSudo(owner string) bool {
	owner = strings.TrimSpace(owner)
	return owner != "" && strings.EqualFold(owner, c.adminOrg)
}

// authorize is the guard's SOLE authorization predicate. A principal may reach
// the admin surface on host iff:
//
//	(global) it is the platform-sudo org  → every surface, tenant + global; OR
//	(tenant) host is a recognized TENANT admin surface (admin.<brand>) AND the
//	         principal is an owner/admin of that brand's org.
//
// FAIL CLOSED by construction: a host that is not a recognized tenant surface —
// the raw global/DO-infra consoles (platform.hanzo.ai, …) and anything unknown —
// returns false here for everyone EXCEPT platform-sudo. So a tenant admin can
// never reach a global surface, and no principal reaches an unrecognized host
// unless it is global sudo.
//
// host MUST be the ingress-set request host (X-Forwarded-Host), never a
// client-controlled value — it is the sole determinant of the tenant org.
func (c *config) authorize(p principal, host string) bool {
	if c.isPlatformSudo(p.owner) {
		return true
	}
	org, ok := tenantOrgForHost(host)
	if !ok {
		return false
	}
	return p.adminOf(org)
}

// ----------------------------------------------------------------------------
// Policy — WHICH question the gate asks
// ----------------------------------------------------------------------------

// policy is the surface-class predicate: given a resolved principal and the
// trusted request host, may it through? It exists because the guard fronts two
// genuinely different KINDS of surface and conflating them is what forced every
// non-admin surface to be admin-only:
//
//   - ADMIN surfaces (platform, studio, commerce-admin, kms/admin) ask
//     "is this an admin of THIS surface's org, or platform sudo?"
//   - AUTHENTICATED surfaces (ci.hanzo.ai, and in time functions/training) ask
//     only "is this anyone at all?", then scope the DATA by the X-Org-Id the
//     guard writes.
//
// Separating them keeps identity resolution (the three-source cascade in
// handleVerify) orthogonal to authorization: one resolver, two policies. The
// policy is chosen by the INGRESS — which verify endpoint a middleware points
// at — and never by anything in the request, so a caller cannot downgrade the
// gate on an admin surface by asking nicely.
type policy struct {
	// name is the policy's identity, echoed in X-Admin-Guard so a verdict can be
	// traced to the policy that produced it without reading the ingress config.
	name string
	// denial is what an authenticated-but-refused API caller is told.
	denial string
	// allow is the predicate. Pure over (principal, trusted host).
	allow func(c *config, p principal, host string) bool
}

// adminPolicy is the original, unchanged gate: platform sudo anywhere, or an
// owner/admin of the org an `admin.<brand>` surface belongs to. Every surface
// wired before 2026-07-27 uses this and its behavior is byte-for-byte what it
// was — the refactor added a second policy, it did not loosen this one.
var adminPolicy = policy{
	name:   "admin",
	denial: "admin access required",
	allow:  func(c *config, p principal, host string) bool { return c.authorize(p, host) },
}

// authnPolicy admits ANY principal the guard could resolve, and nothing else.
// It is deliberately not "allow all": an empty owner means identity resolution
// produced no org, and a surface that scopes its data by X-Org-Id would then
// render every org's rows to a caller with no org. So an empty owner is refused
// here rather than passed through as a blank scope — fail closed on the exact
// field the downstream trusts.
//
// host is ignored ON PURPOSE. This policy grants reach, not visibility: what a
// caller SEES is decided downstream by the X-Org-Id the guard writes from the
// verified `owner` claim. Attaching it to a surface that does not scope by
// X-Org-Id would publish that surface to every authenticated user — so a
// surface must scope before it is wired here.
var authnPolicy = policy{
	name:   "authn",
	denial: "authentication required",
	allow: func(_ *config, p principal, _ string) bool {
		return strings.TrimSpace(p.owner) != ""
	},
}

// stateFields is the arity of the login state cookie payload:
// nonce|verifier|returnTo|policy. The policy is the fourth because the OAuth
// callback is one path shared by every guarded surface and cannot otherwise know
// which question the surface that started the login was asking.
const stateFields = 4

// policyByName recovers a policy from its name as carried in the signed login
// state. It FAILS CLOSED to the admin policy: an unknown or absent name is a
// state this build did not write, and the safe reading of "I don't know which
// gate this is" is the stricter one. Nothing here trusts the browser — the name
// comes out from under the HMAC or the callback has already been refused.
func policyByName(name string) policy {
	if name == authnPolicy.name {
		return authnPolicy
	}
	return adminPolicy
}

// adminSubdomain is the leftmost label that marks a host as a TENANT admin
// surface. Only `admin.<brand>.<domain>` is a tenant surface; every other
// subdomain of a brand (platform.hanzo.ai, studio.hanzo.ai, the bare brand
// domain) is NOT, and so admits global sudo only.
const adminSubdomain = "admin"

// hostOrgDomains maps a brand's REGISTRABLE domain to its IAM org slug (the
// org slug IS the brand key). It MIRRORS the canonical HIP-0111 brand registry
// — hanzoai/cloud brand.go `brands` (Domain + AltDomains → id). It is duplicated
// here rather than imported ON PURPOSE: package cloud is a 75-file dependency
// graph, and admin-guard is a deliberately dependency-light edge binary (the edge
// + net/http only). This table MUST stay in sync with brand.go — brand.go is the
// one source of truth; a brand added there (e.g. osage) MUST be added here to
// enable its tenant admin surface. A domain absent here FAILS CLOSED: its
// admin.<domain> host admits global sudo only.
var hostOrgDomains = map[string]string{
	"hanzo.ai":     "hanzo",
	"hanzo.cloud":  "hanzo",
	"hanzo.app":    "hanzo",
	"lux.network":  "lux",
	"lux.cloud":    "lux",
	"zoo.ngo":      "zoo",
	"zoo.network":  "zoo",
	"zoo.cloud":    "zoo",
	"pars.network": "pars",
	"pars.ai":      "pars",
	"bootno.de":    "bootnode",
}

// tenantOrgForHost resolves the TENANT org an `admin.<brand>.<domain>` surface
// belongs to. It returns (org, true) ONLY when the host's leftmost label is
// exactly "admin" AND the remainder is a registrable brand domain in
// hostOrgDomains (admin.lux.cloud→lux, admin.zoo.cloud→zoo, admin.hanzo.ai→
// hanzo). EVERY other host — the raw global/DO-infra surfaces (platform.hanzo.ai,
// studio.hanzo.ai, the bare brand domains) and anything unrecognized — returns
// ("", false): global-only, fail closed.
//
// The org is derived SOLELY from the trusted request host; there is no path for
// a client to influence which org a host maps to.
func tenantOrgForHost(host string) (string, bool) {
	host = hostOnly(strings.ToLower(strings.TrimSpace(host)))
	label, rest, ok := strings.Cut(host, ".")
	if !ok || label != adminSubdomain {
		return "", false
	}
	org, ok := hostOrgDomains[rest]
	return org, ok
}

// loginOrg is the IAM `organization` hint the guard pins for the interactive
// PKCE login on a host, under the policy the guarded surface is gated by. A
// TENANT admin surface (admin.<brand>) pins that brand's org so a tenant admin
// authenticates into the org the host belongs to; the global/DO-infra surfaces
// (platform.hanzo.ai, …) and any unrecognized host pin the reserved global-admin
// org, preserving today's global-admin login there.
//
// An AUTHN surface pins NOTHING, and the empty string is the whole fix. Pinning
// an org on a surface whose policy admits any principal is a contradiction the
// login layer resolves the wrong way: IAM refuses an authorize whose resolved
// user is not in the pinned org — "federation is not permitted for this
// application" — so a hint of the reserved admin org silently makes an
// admits-anyone surface admin-ONLY. That is precisely the platform-sudo gate
// o11y-guard chose verify-authn to avoid: Observe shows an org its OWN telemetry,
// and gating it on sudo makes it a dashboard its users cannot open.
//
// Pinning the host's BRAND org instead would only move the exclusion — the same
// refusal would then turn away the global admins who are the only ones who can
// reach it today. Both are real users of an authn surface, so the honest hint is
// no hint: let IAM resolve the org from the credential the person presents.
//
// This only steers WHICH login the browser is offered; it grants nothing.
// handleCallback re-runs authorize() before minting a session, so a login that
// resolves an unexpected owner is denied (fail closed), never trusted — which is
// what makes declining to pin safe rather than permissive.
func (c *config) loginOrg(host string, pol policy) string {
	if org, ok := tenantOrgForHost(host); ok {
		return org
	}
	if pol.name == authnPolicy.name {
		return ""
	}
	return c.adminOrg
}
