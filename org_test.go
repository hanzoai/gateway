package gateway

// The org a request ACTS IN and the org that PAYS — the edge half of the org
// switcher, end to end on both transports that carry client traffic: the gin
// middleware (HTTP) and the ZAP relay gate.
//
// A person belongs to several orgs, picks one, and that org must be the one whose
// data they see AND the one whose ledger is charged. The selection rides in
// X-Org-Id, which is also the header the edge MINTS, so the whole contract is: the
// client's copy is deleted at ingress and can only come back if the token's SIGNED
// `orgs` membership set admits it.
//
// These are tenant-isolation and money tests. They must keep passing before any
// merge to main.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hanzoai/authz"
)

// commerceStub stands in for commerce's GET /v1/billing/balance. It records the
// `user` the edge asked about — the org/sub composite whose org half is the LEDGER
// — and always answers with funds, so a test failure means the wrong ledger was
// named, never that the request was merely denied.
func commerceStub(t *testing.T, billed *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*billed = r.URL.Query().Get("user")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(billingResponse{User: *billed, Currency: "usd", Available: 100000})
	}))
}

// orgRequest drives one request through the middleware with the given claims and
// (optional) client org selection, returning the org the backend saw, the home org
// it saw, and the user commerce was asked to bill.
func orgRequest(t *testing.T, claims authz.Claims, selected string) (org, home, billed string) {
	t.Helper()
	commerce := commerceStub(t, &billed)
	defer commerce.Close()

	r, tj, jwksServer := setupMiddlewareWithJWKS(t, func(cfg *AuthConfig) {
		cfg.BillingEnabled = true
		cfg.BillingURL = commerce.URL
		cfg.BillingToken = "s2s"
	})
	defer jwksServer.Close()

	r.GET("/v1/cloud/thing", func(c *gin.Context) {
		org = c.Request.Header.Get("X-Org-Id")
		home = c.Request.Header.Get("X-User-Owner")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/cloud/thing", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims))
	if selected != "" {
		req.Header.Set("X-Org-Id", selected)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("request denied with %d: %s", w.Code, w.Body.String())
	}
	return org, home, billed
}

// memberClaims is a person whose home org is acme and who also belongs to
// beta-team — the ordinary switcher subject, with IAM's signed membership set.
func memberClaims() authz.Claims {
	c := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	c.Owner = "acme"
	c.RegisteredClaims.Subject = "alice"
	c.Orgs = []authz.Membership{{Org: "acme", Role: "admin"}, {Org: "beta-team", Role: "member"}}
	return c
}

// TestOrg_NoSelectionIsUnchanged is the no-op proof for every caller that does not
// switch: with no inbound X-Org-Id the edge mints exactly what it minted before the
// switcher existed — X-Org-Id == X-User-Owner == the JWT owner — and bills the same
// org/sub key. Nothing about a non-switching request moves.
func TestOrg_NoSelectionIsUnchanged(t *testing.T) {
	org, home, billed := orgRequest(t, memberClaims(), "")
	if org != "acme" || home != "acme" {
		t.Errorf("X-Org-Id/X-User-Owner = %q/%q, want acme/acme", org, home)
	}
	if billed != "acme/alice" {
		t.Errorf("billed %q, want acme/alice", billed)
	}
}

// TestOrg_LegacyTokenCannotSwitch proves a token minted before the `orgs` claim
// existed carries an EMPTY membership set, which admits nothing. Such a caller
// stays pinned to home no matter what it selects — the rollout is safe by
// construction, not by deployment ordering.
func TestOrg_LegacyTokenCannotSwitch(t *testing.T) {
	legacy := memberClaims()
	legacy.Orgs = nil

	org, home, billed := orgRequest(t, legacy, "beta-team")
	if org != "acme" || home != "acme" {
		t.Errorf("X-Org-Id/X-User-Owner = %q/%q, want acme/acme (no orgs claim ⟹ no switch)", org, home)
	}
	if billed != "acme/alice" {
		t.Errorf("billed %q, want acme/alice", billed)
	}
}

// TestOrg_MemberSelectionPays is the whole point: a member selects a team org, the
// edge verifies it against the signed set, and BOTH the data scope and the ledger
// move to it. The home org stays on X-User-Owner so identity never moves with the
// selection.
func TestOrg_MemberSelectionPays(t *testing.T) {
	org, home, billed := orgRequest(t, memberClaims(), "beta-team")
	if org != "beta-team" {
		t.Errorf("X-Org-Id = %q, want beta-team (honored member selection)", org)
	}
	if home != "acme" {
		t.Errorf("X-User-Owner = %q, want acme (home never moves)", home)
	}
	if billed != "beta-team/alice" {
		t.Errorf("billed %q, want beta-team/alice — the SELECTED org must be the payer", billed)
	}
}

// TestOrg_NonMemberReadsNothing is the tenant-isolation proof. A caller naming an
// org outside its signed membership set gets its OWN org in every respect: the
// backend is told the caller's org, and commerce is asked about the caller's
// ledger. Nothing of the requested org — not a header, not a balance lookup —
// survives the edge.
func TestOrg_NonMemberReadsNothing(t *testing.T) {
	org, home, billed := orgRequest(t, memberClaims(), "victim")
	if org != "acme" {
		t.Errorf("SECURITY: X-Org-Id = %q, want acme (a non-member selection must fail closed to home)", org)
	}
	if home != "acme" {
		t.Errorf("X-User-Owner = %q, want acme", home)
	}
	if billed != "acme/alice" {
		t.Errorf("SECURITY: billed %q, want acme/alice — a non-member must never touch the requested org's ledger", billed)
	}
	if u, _ := url.QueryUnescape(billed); u == "victim/alice" {
		t.Fatal("SECURITY: the requested org reached commerce")
	}
}

// TestOrg_MasqueradeSpendsAdminLedger pins the operator case, where the two org
// questions deliberately give different answers: a human platform admin may view
// any org (X-Org-Id moves to the customer) but must never spend the customer's
// money (the balance gate stays on the admin ledger).
func TestOrg_MasqueradeSpendsAdminLedger(t *testing.T) {
	operator := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	operator.Owner = "admin"
	operator.RegisteredClaims.Subject = "z"
	// A user token always carries its home org first (store.MemberOrgRefs), which is
	// what distinguishes an operator from an app in the same org.
	operator.Orgs = []authz.Membership{{Org: "admin", Role: "admin"}}

	org, home, billed := orgRequest(t, operator, "customer")
	if org != "customer" {
		t.Errorf("X-Org-Id = %q, want customer (an operator may view any org)", org)
	}
	if home != "admin" {
		t.Errorf("X-User-Owner = %q, want admin", home)
	}
	if billed != "admin/z" {
		t.Errorf("billed %q, want admin/z — an operator must never spend the customer's ledger", billed)
	}
}

// TestOrg_MachineCannotMasquerade closes the escalation the operator branch would
// otherwise open: a client_credentials identity that happens to live in the admin
// org is NOT a platform operator. Without the human narrowing, any admin-org
// machine app could name a victim org and the edge would mint it for every backend
// that trusts the header by design.
func TestOrg_MachineCannotMasquerade(t *testing.T) {
	machine := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	machine.Owner = "admin"
	machine.RegisteredClaims.Subject = "admin/kms-sync"
	// IAM's client_credentials grant signs NO membership set — that is the machine
	// signal. The fixture used to set tokenType "application", a value IAM assigns
	// nowhere, so this test passed against a token that cannot exist while the real
	// escalation stayed open.
	machine.Orgs = nil

	org, _, billed := orgRequest(t, machine, "victim")
	if org != "admin" {
		t.Errorf("SECURITY: X-Org-Id = %q, want admin (a machine is not an operator)", org)
	}
	if billed != "admin/kms-sync" {
		t.Errorf("billed %q, want admin/kms-sync", billed)
	}
}

// relayOrg drives one request through the ZAP relay gate — the transport real
// client traffic arrives on (build_app.go RegisterRelay) — with the given claims
// and client selection, and returns the org the gate put on the envelope.
// forward.Forward.TenantID IS X-Org-Id: the relay lifts it inbound and re-emits it
// as that header at the backend, so this is the same contract on a second wire.
func relayOrg(t *testing.T, claims authz.Claims, selected string) string {
	t.Helper()
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true)
	defer closeJWKS()

	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Authorization": {"Bearer " + tj.signToken(t, claims)},
	})
	f.TenantID = selected // as forward.Forwarder lifts it from the client's X-Org-Id

	deny, err := newGate(cfg)(context.Background(), &f)
	if err != nil || deny != nil {
		t.Fatalf("relay denied a valid JWT: deny=%v err=%v", deny, err)
	}
	return f.TenantID
}

// TestOrg_RelayHonorsSelection proves the org switcher survives the ZAP relay on
// the same terms as the HTTP wire: a member's selection is honored, a non-member's
// is discarded to home, and a selection with no membership claim at all cannot
// move. Cloud re-validates the same Bearer behind this, so what the gate puts on
// the envelope is exactly what cloud's own membership gate gets to see — the whole
// reason the selection has to survive here at all.
func TestOrg_RelayHonorsSelection(t *testing.T) {
	legacy := memberClaims()
	legacy.Orgs = nil

	for _, tc := range []struct {
		name     string
		claims   authz.Claims
		selected string
		want     string
	}{
		{"no selection → home", memberClaims(), "", "acme"},
		{"member team → honored", memberClaims(), "beta-team", "beta-team"},
		{"non-member → fail closed to home", memberClaims(), "victim", "acme"},
		{"no orgs claim → cannot switch", legacy, "beta-team", "acme"},
	} {
		if got := relayOrg(t, tc.claims, tc.selected); got != tc.want {
			t.Errorf("%s: relay TenantID = %q, want %q", tc.name, got, tc.want)
		}
	}
}
