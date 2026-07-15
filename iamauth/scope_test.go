package iamauth

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestClaims_ScopesWireTag pins the WIRE contract with IAM: the membership set
// arrives as `scopes` and each entry as `{scope, role}`. The edge matches claims BY
// JSON TAG and does not import IAM's structs, so a tag drift compiles green on both
// sides and fails only at runtime — as a silently INERT switch (every request falls
// back to home). Building a Claims literal in Go cannot catch that; only decoding
// the wire bytes can.
func TestClaims_ScopesWireTag(t *testing.T) {
	// The `project` claim is the DEFAULT here on purpose: only the decoded scope set
	// can honor the switch below, so the assertion cannot pass off the baseline.
	var c Claims
	if err := json.Unmarshal([]byte(`{
		"owner": "acme",
		"project": "default",
		"scopes": [{"scope": "acme", "role": "admin"}, {"scope": "acme/research", "role": "member"}]
	}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Owner != "acme" {
		t.Fatalf("owner = %q, want acme", c.Owner)
	}
	if len(c.Scopes) != 2 {
		t.Fatalf("scopes = %+v, want 2 entries decoded from the `scopes` claim", c.Scopes)
	}
	if c.Scopes[0].Scope != "acme" || c.Scopes[0].Role != "admin" {
		t.Errorf("scopes[0] = %+v, want {acme admin}", c.Scopes[0])
	}
	if c.Scopes[1].Scope != "acme/research" || c.Scopes[1].Role != "member" {
		t.Errorf("scopes[1] = %+v, want {acme/research member}", c.Scopes[1])
	}
	// The scope set is what authorizes a switch — prove the decoded set actually
	// drives the predicate, not just that the fields populated.
	if got, ok := c.EffectiveProject("acme", "research"); got != "research" || !ok {
		t.Errorf("EffectiveProject over the DECODED set = (%q, %v), want (research, true)", got, ok)
	}
}

// TestEffectiveProject pins the ONE project-switch predicate: a requested project is
// honored only when the subject holds the SCOPE "<org>/<project>", else the request
// falls back to the baseline — never to the requested value. Mirrors TestEffectiveOrg
// one level down the tenancy tree.
func TestEffectiveProject(t *testing.T) {
	// alice acts in home org acme; her `project` claim is the org default; she holds
	// acme/research, and (in team org beta) beta/labs. victim/secret is a scope she
	// does NOT hold and must never reach.
	c := &Claims{
		Owner:   "acme",
		Project: DefaultProject,
		Scopes: []Membership{
			{Scope: "acme", Role: "admin"},
			{Scope: "acme/research", Role: "member"},
			{Scope: "beta", Role: "member"},
			{Scope: "beta/labs", Role: "member"},
		},
	}
	for _, tc := range []struct {
		name, org, requested, want string
		wantSwitched               bool
	}{
		{"no request → baseline (default ⟹ omit)", "acme", "", "", false},
		{"member project → switch", "acme", "research", "research", true},
		{"member project case-insensitive → CANONICAL casing", "acme", "ReSeArCh", "research", true},
		{"explicit default → org-level", "acme", DefaultProject, "", false},
		{"non-member project → fail closed, NEVER the requested value", "acme", "secret", "", false},
		{"invented label → fail closed", "acme", "does-not-exist", "", false},
		// The scope is built from the org being acted in, so another tenant's project
		// can never match — even one the subject holds elsewhere.
		{"foreign org's project → fail closed", "acme", "labs", "", false},
		{"project of the switched org → switch", "beta", "labs", "labs", true},
		{"home org's project while acting in the team org → fail closed", "beta", "research", "", false},
		// A compound request cannot escape the org: scope(org, "a/b") is "org/a/b".
		{"compound request → fail closed", "acme", "../victim/secret", "", false},
	} {
		got, switched := c.EffectiveProject(tc.org, tc.requested)
		if got != tc.want || switched != tc.wantSwitched {
			t.Errorf("%s: EffectiveProject(%q, %q) = (%q, %v), want (%q, %v)",
				tc.name, tc.org, tc.requested, got, switched, tc.want, tc.wantSwitched)
		}
	}
}

// TestEffectiveProject_ClaimBaseline: the `project` claim asserts a project of the
// HOME org, so it is the baseline only while acting there. A switched org must DROP
// it — minting acme's project under org beta would name a project of the wrong
// tenant, which downstream would resolve against beta's projects (matching beta's
// binding, or evading beta's cap).
func TestEffectiveProject_ClaimBaseline(t *testing.T) {
	c := &Claims{
		Owner:   "acme",
		Project: "research", // IAM's assertion: acme/research
		Scopes:  []Membership{{Scope: "beta", Role: "member"}},
	}
	if got, sw := c.EffectiveProject("acme", ""); got != "research" || sw {
		t.Errorf("home org: EffectiveProject = (%q, %v), want (research, false) — the claim is the baseline", got, sw)
	}
	if got, sw := c.EffectiveProject("beta", ""); got != "" || sw {
		t.Errorf("switched org: EffectiveProject = (%q, %v), want (\"\", false) — the HOME-org project claim must not cross", got, sw)
	}
	// Returning to the default project is always available to a member of the org.
	if got, sw := c.EffectiveProject("acme", DefaultProject); got != "" || !sw {
		t.Errorf("default request: EffectiveProject = (%q, %v), want (\"\", true) — org-level is held by every member", got, sw)
	}
}

// TestEffectiveProject_EmptyMembership proves that with no `scopes` claim (a
// pre-rollout token) no project request is ever honored — the live single-project
// behavior is unchanged.
func TestEffectiveProject_EmptyMembership(t *testing.T) {
	c := &Claims{Owner: "acme"}
	if got, sw := c.EffectiveProject("acme", "research"); got != "" || sw {
		t.Fatalf("EffectiveProject with empty membership = (%q, %v), want (\"\", false)", got, sw)
	}
}

// TestEffectiveOrg_CompoundRefused proves an org request can never name a PROJECT
// node. X-Org-Id keys tenant data and the billing subject, so minting a compound
// "acme/research" there would invent a tenant that does not exist.
func TestEffectiveOrg_CompoundRefused(t *testing.T) {
	c := &Claims{Owner: "acme", Scopes: []Membership{{Scope: "acme/research", Role: "member"}}}
	if got, sw := c.EffectiveOrg("acme/research"); got != "acme" || sw {
		t.Fatalf("EffectiveOrg(%q) = (%q, %v), want (acme, false) — a project node is not an org", "acme/research", got, sw)
	}
}

// TestTakeActAs proves the intent headers are read AND deleted in one take, so the
// value the edge authorizes is the one the client sent and no copy survives to reach
// a backend.
func TestTakeActAs(t *testing.T) {
	r := req(map[string]string{ActAsOrgHeader: "beta", ActAsProjectHeader: "labs", "X-Real-Header": "keep"})
	got := TakeActAs(r)
	if got.Org != "beta" || got.Project != "labs" {
		t.Fatalf("TakeActAs = %+v, want {beta labs}", got)
	}
	for _, h := range ActAsHeaderNames {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("intent header %q survived the take: %q", h, v)
		}
	}
	if r.Header.Get("X-Real-Header") != "keep" {
		t.Error("non-intent header must survive")
	}
}

// TestActAs_NotInStripList pins WHY the intent headers are absent from the strip
// list: the strip runs at ingress, BEFORE the mint, so stripping an intent there
// would delete the value the mint must read and the switch would silently never
// work. They are consumed by TakeActAs instead — proven above.
func TestActAs_NotInStripList(t *testing.T) {
	for _, name := range StripIdentityHeaderNames {
		for _, intent := range ActAsHeaderNames {
			if http.CanonicalHeaderKey(name) == http.CanonicalHeaderKey(intent) {
				t.Fatalf("%q is an act-as INTENT (an input to the mint) and must not be stripped before the mint reads it", intent)
			}
		}
	}
}

// TestInjectIdentity_ProjectSwitch proves the ingress mints X-Project-Id from a VALID
// member switch and consumes the intent header.
func TestInjectIdentity_ProjectSwitch(t *testing.T) {
	r := req(map[string]string{ActAsProjectHeader: "research"})
	InjectIdentity(r, &Claims{Owner: "acme", Scopes: []Membership{{Scope: "acme/research", Role: "member"}}})
	if got := r.Header.Get("X-Project-Id"); got != "research" {
		t.Errorf("X-Project-Id = %q, want research (honored member switch)", got)
	}
	if got := r.Header.Get("X-Org-Id"); got != "acme" {
		t.Errorf("X-Org-Id = %q, want acme", got)
	}
	if got := r.Header.Get(ActAsProjectHeader); got != "" {
		t.Errorf("X-Act-As-Project must be consumed, still present: %q", got)
	}
}

// TestInjectIdentity_ProjectSwitchRefused proves a switch to a project OUTSIDE the
// scope set fails closed: no X-Project-Id is minted, and above all the REQUESTED
// value is never minted — a forged X-Act-As-Project can never select another
// tenant's project or evade a project-scoped cap.
func TestInjectIdentity_ProjectSwitchRefused(t *testing.T) {
	r := req(map[string]string{ActAsProjectHeader: "secret"})
	InjectIdentity(r, &Claims{Owner: "acme", Scopes: []Membership{{Scope: "victim/secret", Role: "member"}}})
	if got := r.Header.Get("X-Project-Id"); got != "" {
		t.Errorf("X-Project-Id = %q, want \"\" — a non-member project must fail closed", got)
	}
}

// TestInjectIdentity_ForgedProjectHeaderNeverSurvives: the client copy of the MINTED
// header is not an intent — it is stripped at ingress and can never be re-minted from
// itself. Only the claim/membership path can set it.
func TestInjectIdentity_ForgedProjectHeaderNeverSurvives(t *testing.T) {
	r := req(map[string]string{"X-Project-Id": "victim-project"})
	StripIdentityHeaders(r)
	InjectIdentity(r, &Claims{Owner: "acme", Scopes: []Membership{{Scope: "acme/research", Role: "member"}}})
	if got := r.Header.Get("X-Project-Id"); got != "" {
		t.Fatalf("X-Project-Id = %q, want \"\" — a forged client copy must never survive", got)
	}
}
