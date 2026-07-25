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

	"github.com/hanzoai/gateway/v2/iamauth"
)

// authz.go is the guard's AUTHORIZATION CORE — the one place that answers "may
// this principal reach the admin surface on this host?". It is deliberately
// isolated from the HTTP/OAuth mechanics in main.go so it can be read and
// attacked as a unit: pure predicates over a resolved principal + a request
// host, no I/O, no request parsing. Every identity source in main.go collapses
// to a principal and calls authorize(); nothing else makes an allow decision.

// principal is the resolved, TRUSTED identity the guard authorizes. It is the
// SAME shape regardless of source (guard session cookie, Bearer/Basic JWT, IAM
// get-account), so authorization is a pure function of a principal + a host.
//
//   - owner   : the subject's HOME org slug (Casdoor `owner`) — identity anchor.
//   - isAdmin : the subject is an org-level admin/owner of its HOME org
//     (Casdoor `isAdmin`). This is NEVER the platform-sudo bit (that is owner ==
//     adminOrg); it is the per-org owner flag, so it authorizes ONLY the home
//     org's own tenant surface.
//   - orgs    : the full org-membership set with per-org roles. Populated ONLY on
//     the JWT path (the token carries it); nil on the cookie / get-account paths,
//     which therefore authorize a HOME-org admin only. Fail-closed: a nil set
//     never widens access, it only ever fails to recognize a non-home admin.
type principal struct {
	owner   string
	isAdmin bool
	orgs    []iamauth.Membership
}

// principalFromClaims lifts a validated JWT into a principal. The claims are
// IAM-signed (issuer + audience + expiry enforced by iamauth), so owner,
// isAdmin, and the membership set are trusted, not client-forgeable.
func principalFromClaims(c *iamauth.Claims) principal {
	return principal{owner: c.Owner, isAdmin: c.IsAdmin, orgs: c.Orgs}
}

// adminOf reports whether the principal holds an owner/admin role in org. Two
// independent, trusted signals satisfy it, mirroring iamauth's model:
//
//   - the org IS the subject's home org AND it is a home-org admin (isAdmin), or
//   - the subject carries an explicit membership in org with role owner|admin.
//
// A plain `member` role never satisfies it — so a regular member of the lux org
// is NOT a lux tenant admin. Comparison is case- and space-insensitive to match
// iamauth (Casdoor may vary casing); an empty org is never an admin target.
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
		role := strings.TrimSpace(m.Role)
		if strings.EqualFold(role, "owner") || strings.EqualFold(role, "admin") {
			return true
		}
	}
	return false
}

// isPlatformSudo reports whether owner is the reserved global-admin org
// (owner == adminOrg). This is the ONE platform-sudo predicate, byte-for-byte
// the same meaning iamauth.PlatformSudo enforces on the other side of the trust
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

// adminSubdomain is the leftmost label that marks a host as a TENANT admin
// surface. Only `admin.<brand>.<domain>` is a tenant surface; every other
// subdomain of a brand (platform.hanzo.ai, studio.hanzo.ai, the bare brand
// domain) is NOT, and so admits global sudo only.
const adminSubdomain = "admin"

// hostOrgDomains maps a brand's REGISTRABLE domain to its Casdoor org slug (the
// org slug IS the brand key). It MIRRORS the canonical HIP-0111 brand registry
// — hanzoai/cloud brand.go `brands` (Domain + AltDomains → id). It is duplicated
// here rather than imported ON PURPOSE: package cloud is a 75-file dependency
// graph, and admin-guard is a deliberately dependency-light edge binary (iamauth
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

// loginOrg is the Casdoor `organization` hint the guard pins for the interactive
// PKCE login on a host. A TENANT admin surface (admin.<brand>) pins that brand's
// org so a tenant admin authenticates into the org the host belongs to; the
// global/DO-infra surfaces (platform.hanzo.ai, …) and any unrecognized host pin
// the reserved global-admin org, preserving today's global-admin login there.
//
// This only steers WHICH login the browser is offered; it grants nothing.
// handleCallback re-runs authorize() before minting a session, so a login that
// resolves an unexpected owner is denied (fail closed), never trusted.
func (c *config) loginOrg(host string) string {
	if org, ok := tenantOrgForHost(host); ok {
		return org
	}
	return c.adminOrg
}
