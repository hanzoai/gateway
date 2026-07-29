package iamauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func req(headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://goproxy.hanzo.ai/golang.org/x/mod/@v/list", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestBearerToken(t *testing.T) {
	if got := BearerToken(req(map[string]string{"Authorization": "Bearer abc.def.ghi"})); got != "abc.def.ghi" {
		t.Fatalf("Bearer: got %q", got)
	}
	if got := BearerToken(req(map[string]string{"X-Authorization": "Bearer xyz"})); got != "xyz" {
		t.Fatalf("X-Authorization Bearer: got %q", got)
	}
	if got := BearerToken(req(map[string]string{"Authorization": basic("u", "p")})); got != "" {
		t.Fatalf("Basic must not parse as Bearer: got %q", got)
	}
}

// The canonical `go`/.netrc proxy auth path: credential arrives as HTTP
// Basic, token in the password field.
func TestBasicToken_PasswordIsToken(t *testing.T) {
	if got := BasicToken(req(map[string]string{"Authorization": basic("z@hanzo.ai", "the-iam-jwt")})); got != "the-iam-jwt" {
		t.Fatalf("password token: got %q", got)
	}
	// Empty password → fall back to username (token-as-username clients).
	if got := BasicToken(req(map[string]string{"Authorization": basic("the-iam-jwt", "")})); got != "the-iam-jwt" {
		t.Fatalf("username fallback: got %q", got)
	}
	if got := BasicToken(req(map[string]string{"Authorization": "Bearer abc"})); got != "" {
		t.Fatalf("Bearer must not parse as Basic: got %q", got)
	}
	if got := BasicToken(req(map[string]string{"Authorization": "Basic not-base64!!"})); got != "" {
		t.Fatalf("bad base64 must yield empty: got %q", got)
	}
}

func TestExtractToken_Precedence(t *testing.T) {
	// Bearer wins over Basic.
	r := req(map[string]string{"Authorization": "Bearer bearer-wins"})
	r.Header.Add("X-Authorization", "Bearer ignored")
	if got := ExtractToken(r); got != "bearer-wins" {
		t.Fatalf("precedence Bearer: got %q", got)
	}
	// Basic when no Bearer.
	if got := ExtractToken(req(map[string]string{"Authorization": basic("u", "basic-token")})); got != "basic-token" {
		t.Fatalf("precedence Basic: got %q", got)
	}
	// Cookie when neither.
	r = req(nil)
	r.AddCookie(&http.Cookie{Name: "iam_access_token", Value: "cookie-token"})
	if got := ExtractToken(r); got != "cookie-token" {
		t.Fatalf("precedence cookie: got %q", got)
	}
}

func TestIsAPIKey(t *testing.T) {
	for _, k := range []string{"hk-x", "sk-x", "fw_x", "hz_x", "pk-x"} {
		if !IsAPIKey(k) {
			t.Fatalf("%q should be an API key", k)
		}
	}
	if IsAPIKey("eyJhbGci.jwt.sig") {
		t.Fatal("JWT must not be treated as API key")
	}
}

// Strip-list MUST cover every minted header — the trust boundary contract.
func TestStripList_CoversAllMinted(t *testing.T) {
	for _, h := range MintedIdentityHeaders {
		r := req(map[string]string{h: "forged"})
		StripIdentityHeaders(r)
		if r.Header.Get(h) != "" {
			t.Fatalf("minted header %q not stripped", h)
		}
	}
}

// TestStripIdentityHeaders_NeutralExactAndVendorBackstop: neutral identity headers
// are stripped by exact name; a NON-identity header survives; and the gateway's
// Go-side defensive backstop still deletes any stray vendor-prefixed header
// (brand-neutral: it only deletes vendor junk, on every deployment). The ingress
// strip needs no wildcard because identity headers are all neutral now.
func TestStripIdentityHeaders_NeutralExactAndVendorBackstop(t *testing.T) {
	r := req(map[string]string{
		"X-User-Id":     "forged",
		"X-Org-Id":      "forged",
		"X-User-Role":   "admin",
		"X-Tenant-Id":   "t",
		"X-IAM-Foo":     "x",
		"X-HANZO-Bar":   "y",
		"X-Real-Header": "keep",
	})
	StripIdentityHeaders(r)
	for _, h := range []string{"X-User-Id", "X-Org-Id", "X-User-Role", "X-Tenant-Id", "X-Iam-Foo", "X-Hanzo-Bar"} {
		if r.Header.Get(h) != "" {
			t.Fatalf("header %q should be stripped", h)
		}
	}
	if r.Header.Get("X-Real-Header") != "keep" {
		t.Fatal("non-identity header must survive")
	}
}

func TestInjectIdentity(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "hanzo", Email: "z@hanzo.ai", IsAdmin: true}, "")
	// UserID falls back to preferred_username/name when sub empty; here all empty.
	if r.Header.Get("X-Org-Id") != "hanzo" {
		t.Fatalf("X-Org-Id: got %q", r.Header.Get("X-Org-Id"))
	}
	if r.Header.Get("X-User-Email") != "z@hanzo.ai" {
		t.Fatalf("X-User-Email: got %q", r.Header.Get("X-User-Email"))
	}
	// An ORG-level admin (owner="hanzo") is NOT a platform admin, and the header
	// that carries platform authority is X-User-IsAdmin — that is what cloud,
	// commerce and every gate in the fleet read it as.
	//
	// This assertion used to be inverted: it required X-User-IsAdmin for this
	// org-level admin and only checked that the long-retired
	// X-User-IsGlobalAdmin stayed empty. Two repos held opposite beliefs about
	// which header means what, each internally consistent, and this test wrote
	// the wrong one down — so every org owner was minted as a platform admin.
	if r.Header.Get("X-User-IsAdmin") != "" {
		t.Fatalf("X-User-IsAdmin minted for an ORG-level admin: got %q", r.Header.Get("X-User-IsAdmin"))
	}
	if r.Header.Get("X-User-IsOrgAdmin") != "true" {
		t.Fatalf("X-User-IsOrgAdmin: got %q", r.Header.Get("X-User-IsOrgAdmin"))
	}
	if r.Header.Get("X-User-IsGlobalAdmin") != "" {
		t.Fatalf("X-User-IsGlobalAdmin minted: got %q", r.Header.Get("X-User-IsGlobalAdmin"))
	}
	// No project claim ⟹ default project ⟹ X-Project-Id omitted (present iff
	// a non-default project is in scope), preserving single-project behavior.
	if v := r.Header.Get("X-Project-Id"); v != "" {
		t.Fatalf("X-Project-Id must be omitted for the default project, got %q", v)
	}
}

// TestInjectIdentity_NoPlatformAdminHeader proves InjectIdentity mints NO platform-
// admin boolean header. Platform sudo is org == AdminOrg (carried by X-Org-Id), with
// no boolean — so even an admin-org principal gets no X-User-IsGlobalAdmin.
func TestInjectIdentity_NoPlatformAdminHeader(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "admin", IsAdmin: true}, "")
	if v := r.Header.Get("X-User-IsGlobalAdmin"); v != "" {
		t.Fatalf("X-User-IsGlobalAdmin must never be minted (platform sudo = org==admin), got %q", v)
	}
	// The platform-sudo signal is the org itself, carried by X-Org-Id.
	if got := r.Header.Get("X-Org-Id"); got != "admin" {
		t.Fatalf("X-Org-Id: got %q want \"admin\" (the platform-sudo signal)", got)
	}
}

// member is the claim set of a person whose home org is acme and who also belongs
// to beta-team — the ordinary org-switcher subject.
func member() *Claims {
	return &Claims{Owner: "acme", Orgs: []Membership{{Org: "acme", Role: "admin"}, {Org: "beta-team", Role: "member"}}}
}

// TestEffectiveOrg pins the ONE org-switch predicate: a selected org is honored
// only when the subject is a member of it (the home org is always an implicit
// member), else the request falls back to the home org — a caller can never act
// beyond its IAM-granted membership set.
//
// The comparison is VERBATIM. The case variants below must NOT switch: they are
// the fold that would let a member of "acme" select a DIFFERENT org named "ACME".
// Cloud's isMember answers the same way, so the edge and the in-binary path agree.
func TestEffectiveOrg(t *testing.T) {
	c := member()
	for _, tc := range []struct {
		name, selected, wantOrg string
		wantSwitched            bool
	}{
		{"no selection → home", "", "acme", false},
		{"select home → home (no switch)", "acme", "acme", false},
		{"member team → switch", "beta-team", "beta-team", true},
		{"non-member → fail closed to home", "victim", "acme", false},
		{"home in another case is a DIFFERENT org → home", "ACME", "acme", false},
		{"member team in another case is a DIFFERENT org → home", "Beta-Team", "acme", false},
		{"trailing space must not fold onto the member slug", "beta-team ", "acme", false},
		{"zero-width rune must not fold onto the member slug", "beta-​team", "acme", false},
	} {
		gotOrg, gotSwitched := c.EffectiveOrg(tc.selected)
		if gotOrg != tc.wantOrg || gotSwitched != tc.wantSwitched {
			t.Errorf("%s: EffectiveOrg(%q) = (%q, %v), want (%q, %v)", tc.name, tc.selected, gotOrg, gotSwitched, tc.wantOrg, tc.wantSwitched)
		}
	}
}

// TestEffectiveOrg_EmptyMembership proves that with no `orgs` claim (a legacy
// token, an opaque key, a machine principal — IAM mints `orgs` for none of them)
// only the home org is ever effective. An empty set admits nothing, which is
// exactly the pre-claim behavior.
func TestEffectiveOrg_EmptyMembership(t *testing.T) {
	c := &Claims{Owner: "acme"}
	if org, sw := c.EffectiveOrg("beta-team"); org != "acme" || sw {
		t.Fatalf("EffectiveOrg with empty membership = (%q, %v), want (acme, false)", org, sw)
	}
}

// TestEffectiveOrg_Masquerade proves a HUMAN platform operator (owner == AdminOrg)
// may act in any org without a membership claim — the cross-org view — while a
// MACHINE identity in the same admin org may not. Without the machine narrowing an
// admin-org client_credentials app could name a victim org and the edge would mint
// it for every backend that trusts the header.
func TestEffectiveOrg_Masquerade(t *testing.T) {
	human := &Claims{Owner: AdminOrg}
	if org, sw := human.EffectiveOrg("customer"); org != "customer" || !sw {
		t.Errorf("human operator: EffectiveOrg(customer) = (%q, %v), want (customer, true)", org, sw)
	}
	machine := &Claims{Owner: AdminOrg, Type: "application"}
	if org, sw := machine.EffectiveOrg("customer"); org != AdminOrg || sw {
		t.Errorf("machine in admin org: EffectiveOrg(customer) = (%q, %v), want (admin, false)", org, sw)
	}
	kms := &Claims{Owner: AdminOrg}
	kms.Audience = []string{AdminOrg + "-platform-kms"}
	if org, sw := kms.EffectiveOrg("customer"); org != AdminOrg || sw {
		t.Errorf("kms machine: EffectiveOrg(customer) = (%q, %v), want (admin, false)", org, sw)
	}
}

// TestLedgerOrg pins the SECOND org question — who PAYS — against the first.
// For everyone but an operator the two answers are the same value, which is the
// product: the org you picked is the org that is billed. For a masquerading
// operator they deliberately diverge: they read the customer's org and spend the
// admin's money, never the customer's.
func TestLedgerOrg(t *testing.T) {
	c := member()
	for _, tc := range []struct{ name, selected, want string }{
		{"no selection → home pays", "", "acme"},
		{"member team → the SELECTED org pays", "beta-team", "beta-team"},
		{"non-member → home pays", "victim", "acme"},
	} {
		if got := c.LedgerOrg(tc.selected); got != tc.want {
			t.Errorf("%s: LedgerOrg(%q) = %q, want %q", tc.name, tc.selected, got, tc.want)
		}
	}
	operator := &Claims{Owner: AdminOrg}
	if got := operator.LedgerOrg("customer"); got != AdminOrg {
		t.Errorf("masquerade must spend the ADMIN ledger: LedgerOrg(customer) = %q, want %q", got, AdminOrg)
	}
	if org, _ := operator.EffectiveOrg("customer"); org != "customer" {
		t.Errorf("masquerade must still READ the customer org: EffectiveOrg(customer) = %q", org)
	}
}

// TestOrgSelection_NoOp is the regression proof for every caller that does NOT
// switch: with no inbound X-Org-Id the edge mints exactly what it minted before
// the switcher existed — X-Org-Id == X-User-Owner == the JWT owner — for an
// ordinary member, a legacy token with no `orgs` claim, and a platform operator.
func TestOrgSelection_NoOp(t *testing.T) {
	for _, c := range []*Claims{
		member(),
		{Owner: "acme"},
		{Owner: AdminOrg},
	} {
		r := req(nil)
		selected := StripIdentityHeaders(r)
		if selected != "" {
			t.Fatalf("no inbound X-Org-Id must capture no selection, got %q", selected)
		}
		InjectIdentity(r, c, selected)
		if got := r.Header.Get(OrgHeader); got != c.Owner {
			t.Errorf("owner=%q: X-Org-Id = %q, want the home org unchanged", c.Owner, got)
		}
		if got := r.Header.Get("X-User-Owner"); got != c.Owner {
			t.Errorf("owner=%q: X-User-Owner = %q, want the home org", c.Owner, got)
		}
		if got := c.LedgerOrg(selected); got != c.Owner {
			t.Errorf("owner=%q: LedgerOrg = %q, want the home org", c.Owner, got)
		}
	}
}

// TestOrgSelection_Honored is the end-to-end edge contract for a real switch: the
// client sends its selection in X-Org-Id, the strip captures and DELETES it, and
// the mint puts the membership-verified value back. X-User-Owner stays on the home
// org, so identity and payer never move with the data scope.
func TestOrgSelection_Honored(t *testing.T) {
	r := req(map[string]string{OrgHeader: "beta-team"})
	selected := StripIdentityHeaders(r)
	if selected != "beta-team" {
		t.Fatalf("strip must capture the selection, got %q", selected)
	}
	if got := r.Header.Get(OrgHeader); got != "" {
		t.Fatalf("the client's X-Org-Id must be deleted by the strip, still present: %q", got)
	}
	InjectIdentity(r, member(), selected)
	if got := r.Header.Get(OrgHeader); got != "beta-team" {
		t.Errorf("X-Org-Id = %q, want beta-team (honored member selection)", got)
	}
	if got := r.Header.Get("X-User-Owner"); got != "acme" {
		t.Errorf("X-User-Owner = %q, want acme (home unchanged by a switch)", got)
	}
}

// TestOrgSelection_Discarded is the tenant-isolation proof: a selection outside
// the signed membership set leaves NOTHING of the requested org on the request.
// The refusal is silent and byte-identical to "no selection" — the caller reads
// their own org, so a revoked membership degrades to their own data rather than
// to a 403 the UI cannot explain.
func TestOrgSelection_Discarded(t *testing.T) {
	victim := req(map[string]string{OrgHeader: "victim"})
	InjectIdentity(victim, member(), StripIdentityHeaders(victim))

	none := req(nil)
	InjectIdentity(none, member(), StripIdentityHeaders(none))

	if got := victim.Header.Get(OrgHeader); got != "acme" {
		t.Fatalf("X-Org-Id = %q, want acme (a non-member selection must fail closed to home)", got)
	}
	for h, want := range none.Header {
		if got := victim.Header[h]; len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
			t.Fatalf("refused selection changed %s: %q vs %q (refusal must be indistinguishable from no selection)", h, got, want)
		}
	}
	for h := range victim.Header {
		if _, ok := none.Header[h]; !ok {
			t.Fatalf("refused selection added header %s — nothing of the requested org may survive", h)
		}
	}
}

// TestClaims_PlatformSudo pins the ONE platform-sudo predicate: membership in the
// reserved AdminOrg (owner=="admin"), case/space-insensitive. There is no boolean
// flag; a plain org-level IsAdmin (an org owner) must NOT qualify — that was the
// free-money hole. Mirrors commerce/cloud/iam gating on org == AdminOrg.
func TestClaims_PlatformSudo(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
		want   bool
	}{
		{"nil", nil, false},
		{"admin-org", &Claims{Owner: "admin"}, true},
		{"admin-org-mixedcase", &Claims{Owner: "Admin"}, true},
		{"admin-org-spaces", &Claims{Owner: " admin "}, true},
		{"org-admin-not-platform", &Claims{Owner: "maxpower", IsAdmin: true}, false},
		{"plain-user", &Claims{Owner: "hanzo"}, false},
	}
	for _, tc := range cases {
		if got := tc.claims.PlatformSudo(); got != tc.want {
			t.Fatalf("%s: PlatformSudo()=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestInjectIdentity_Project: a non-default `project` claim is minted into
// X-Project-Id exactly like `owner`→X-Org-Id; the literal default is omitted.
func TestInjectIdentity_Project(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "acme", Project: "research"}, "")
	if got := r.Header.Get("X-Project-Id"); got != "research" {
		t.Fatalf("X-Project-Id: got %q, want %q", got, "research")
	}
	// The literal default project mints nothing (absent header ⟺ default scope).
	r = req(nil)
	InjectIdentity(r, &Claims{Owner: "acme", Project: DefaultProject}, "")
	if got := r.Header.Get("X-Project-Id"); got != "" {
		t.Fatalf("X-Project-Id must be omitted for %q, got %q", DefaultProject, got)
	}
}

func TestClaims_UserIDFallback(t *testing.T) {
	c := &Claims{PreferredUsername: "alice"}
	if c.UserID() != "alice" {
		t.Fatalf("preferred_username fallback: got %q", c.UserID())
	}
	c = &Claims{Name: "Bob"}
	if c.UserID() != "Bob" {
		t.Fatalf("name fallback: got %q", c.UserID())
	}
}
