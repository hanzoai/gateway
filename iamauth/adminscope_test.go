package iamauth

import (
	"net/http"
	"testing"
)

// TWO ADMIN SCOPES, and the edge mints them apart. Conflating them is a
// privilege escalation, and it was live: X-User-IsAdmin — the header every
// backend gates platform authority on — was minted from c.IsAdmin, the ORG-role
// bit that PlatformSudo's own comment says is "deliberately NOT trusted". Any
// org owner therefore arrived as a platform admin.

func mint(t *testing.T, c *Claims, selected string) http.Header {
	t.Helper()
	r, err := http.NewRequest("GET", "http://x/v1/anything", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	InjectIdentity(r, c, selected)
	return r.Header
}

// The escalation, pinned: an org owner is NOT a platform admin.
func TestOrgAdminIsNotPlatformAdmin(t *testing.T) {
	h := mint(t, &Claims{
		Owner:   "acme",
		IsAdmin: true, // IAM's ORG-role bit
		Orgs:    []Membership{{Org: "acme", Role: "admin"}},
	}, "")

	if h.Get("X-User-IsAdmin") == "true" {
		t.Fatal("an org admin was minted as PLATFORM admin — this is the escalation")
	}
	if h.Get("X-User-IsOrgAdmin") != "true" {
		t.Fatal("an org admin lost its own org-admin scope")
	}
	if got := h.Get("X-Org-Id"); got != "acme" {
		t.Fatalf("X-Org-Id = %q, want acme", got)
	}
}

// A real platform operator gets platform sudo.
func TestPlatformOperatorGetsSudo(t *testing.T) {
	h := mint(t, &Claims{Owner: AdminOrg, Orgs: []Membership{{Org: AdminOrg, Role: "admin"}}}, "")
	if h.Get("X-User-IsAdmin") != "true" {
		t.Fatal("a human in the admin org did not get platform sudo")
	}
}

// A MACHINE in the admin org never gets platform sudo, however its org-role bit
// reads — otherwise any admin-org client_credentials app inherits cross-org reach.
func TestAdminOrgMachineNeverGetsSudo(t *testing.T) {
	h := mint(t, &Claims{Owner: AdminOrg, IsAdmin: true, Type: "application"}, "")
	if h.Get("X-User-IsAdmin") == "true" {
		t.Fatal("an admin-org MACHINE was minted as platform admin")
	}
	if h.Get("X-User-IsOrgAdmin") == "true" {
		t.Fatal("a machine was granted an org's self-service admin surface")
	}
}

// An operator viewing ANOTHER tenant carries platform sudo but NOT that tenant's
// self-service authority: the org-admin scope follows the effective org, and the
// operator does not administer it.
func TestOperatorViewingTenantIsNotThatTenantsOrgAdmin(t *testing.T) {
	h := mint(t, &Claims{Owner: AdminOrg, IsAdmin: true, Orgs: []Membership{{Org: AdminOrg, Role: "admin"}}}, "victim")
	if h.Get("X-Org-Id") != "victim" {
		t.Fatalf("masquerade did not take effect: X-Org-Id = %q", h.Get("X-Org-Id"))
	}
	if h.Get("X-User-IsAdmin") != "true" {
		t.Fatal("the operator lost platform sudo")
	}
	if h.Get("X-User-IsOrgAdmin") == "true" {
		t.Fatal("the operator was granted the victim org's own admin scope")
	}
}

// An org OWNER administers their org as surely as an `admin` does. Matching only
// "admin" refused every self-serve founder from their own admin surface.
func TestOrgOwnerRoleAdministersItsOwnOrg(t *testing.T) {
	h := mint(t, &Claims{Owner: "acme", Orgs: []Membership{{Org: "acme", Role: "owner"}}}, "")
	if h.Get("X-User-IsOrgAdmin") != "true" {
		t.Fatal("an org owner was refused its own org-admin scope")
	}
}

// A plain member is neither.
func TestMemberIsNeitherScope(t *testing.T) {
	h := mint(t, &Claims{Owner: "acme", Orgs: []Membership{{Org: "acme", Role: "member"}}}, "")
	if h.Get("X-User-IsAdmin") == "true" || h.Get("X-User-IsOrgAdmin") == "true" {
		t.Fatalf("a member carried an admin scope: %v", h)
	}
}
