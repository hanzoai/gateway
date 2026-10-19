// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

// Platform authority on both transports — the HTTP edge (writeIdentity: the
// X-User-IsAdmin header and the money bit-field) and the ZAP relay (the gate:
// Forward.IsAdmin and Forward.Permissions) — is authz.Claims.Sudo and nothing
// else: a PERSON whose home org, orgs[0], is the reserved admin org, compared
// verbatim. A membership of admin held from a brand org, an admin-org program and
// an org whose name differs from admin only in case are none of them.

import (
	"context"
	"net/http"
	"testing"

	"github.com/hanzoai/authz"
)

type sudoCase struct {
	name  string
	shape func(*authz.Claims)
	super bool
}

var sudoCases = []sudoCase{
	{"a person whose home org is admin", func(c *authz.Claims) {
		c.Orgs = []authz.Membership{{Org: authz.AdminOrg, Role: authz.Owner}}
	}, true},
	{"a brand person holding an admin membership", func(c *authz.Claims) {
		c.Orgs = []authz.Membership{{Org: "hanzo", Role: authz.Owner}, {Org: authz.AdminOrg, Role: authz.Admin}}
	}, false},
	{"an admin-org program", func(c *authz.Claims) {
		c.Owner, c.Type, c.Orgs = authz.AdminOrg, authz.Program, nil
	}, false},
	{"an admin-org token with no membership set", func(c *authz.Claims) {
		c.Owner, c.Orgs = authz.AdminOrg, nil
	}, false},
	{"an org admin of a brand org", func(c *authz.Claims) {
		c.IsAdmin, c.Orgs = true, []authz.Membership{{Org: "hanzo", Role: authz.Admin}}
	}, false},
	{"an org named Admin", func(c *authz.Claims) {
		c.Orgs = []authz.Membership{{Org: "Admin", Role: authz.Owner}}
	}, false},
	{"an org named ADMIN", func(c *authz.Claims) {
		c.Orgs = []authz.Membership{{Org: "ADMIN", Role: authz.Owner}}
	}, false},
}

func TestSudoOnTheHTTPEdge(t *testing.T) {
	for _, tc := range sudoCases {
		c := validClaims("https://hanzo.id", "https://api.hanzo.ai")
		tc.shape(&c)
		h := http.Header{}
		writeIdentity(h, &c, "")
		if got := h.Get(authz.HeaderUserAdmin) == "true"; got != tc.super {
			t.Errorf("%s: X-User-IsAdmin = %q, want SuperAdmin %v", tc.name, h.Get(authz.HeaderUserAdmin), tc.super)
		}
		if got := moneyBits(&c)&permissionBits["admin"] != 0; got != tc.super {
			t.Errorf("%s: the Admin money bit = %v, want %v", tc.name, got, tc.super)
		}
	}
}

func TestSudoOnTheRelay(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true)
	defer closeJWKS()
	gate := newGate(cfg)
	for _, tc := range sudoCases {
		c := validClaims(cfg.Issuer, cfg.Audiences[0])
		tc.shape(&c)
		f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
			"Authorization": {"Bearer " + tj.signToken(t, c)},
		})
		if deny, err := gate(context.Background(), &f); err != nil || deny != nil {
			// A token the gate refuses carries no authority at all, which is never
			// a SuperAdmin; only the SuperAdmin case must get through.
			if tc.super {
				t.Fatalf("%s: denied (%v, %v)", tc.name, deny, err)
			}
			continue
		}
		if f.IsAdmin != tc.super {
			t.Errorf("%s: Forward.IsAdmin = %v, want %v", tc.name, f.IsAdmin, tc.super)
		}
		if got := f.Permissions&permissionBits["admin"] != 0; got != tc.super {
			t.Errorf("%s: the Admin money bit on the relay = %v, want %v", tc.name, got, tc.super)
		}
	}
}
