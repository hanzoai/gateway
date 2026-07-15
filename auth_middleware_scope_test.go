package gateway

// Scope-switch security tests for the auth middleware — the LIVE edge.
//
// Every token here is REALLY SIGNED and carries the `scopes` claim ON THE WIRE, so
// the middleware parses it exactly as it would a hanzo.id token. This is deliberate:
// the org/project switch reads claims IAM does not emit yet, so a test that asserted
// these headers against a token WITHOUT the claims would pass vacuously — proving
// nothing about the predicate it names.
//
// What is pinned here: a project is minted only from the token's membership set; a
// forged or foreign one is refused; an act-as INTENT never reaches a backend on any
// route class; and the billing-account hint carries no billing authority.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hanzoai/gateway/v2/iamauth"
)

// scopeToken signs a token for alice@<owner> carrying a real `scopes` membership set
// and `project` claim — the shape IAM emits under Model B (HIP-0111).
func scopeToken(t *testing.T, tj *testJWKS, owner, project string, scopes ...string) string {
	t.Helper()
	now := time.Now()
	set := make([]map[string]string, 0, len(scopes))
	for _, s := range scopes {
		set = append(set, map[string]string{"scope": s, "role": "member"})
	}
	claims := map[string]interface{}{
		"iss":   "https://hanzo.id",
		"sub":   "alice",
		"aud":   []string{"https://api.hanzo.ai"},
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"owner": owner,
		"email": "alice@hanzo.ai",
	}
	if project != "" {
		claims["project"] = project
	}
	if len(set) > 0 {
		claims["scopes"] = set
	}
	return tj.signToken(t, claims)
}

// backend captures exactly what the edge forwarded — the assertion surface for every
// test below. Asserting a status code would prove nothing here: the question is never
// "was it allowed" but "WHICH scope did the backend receive".
type backend struct {
	org, project, owner, billing string
	actAsOrg, actAsProject       string
	seen                         bool
}

// edge wires the real NewAuthMiddleware to a test JWKS and records the forwarded
// headers. Returns the engine, the JWKS helper, and the backend's view.
func edge(t *testing.T, tune func(*AuthConfig)) (*gin.Engine, *testJWKS, *backend) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	t.Cleanup(jwksServer.Close)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     jwksServer.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: true,
	}
	if tune != nil {
		tune(&cfg)
	}
	got := &backend{}
	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))
	record := func(c *gin.Context) {
		h := c.Request.Header
		got.seen = true
		got.org, got.project = h.Get("X-Org-Id"), h.Get("X-Project-Id")
		got.owner, got.billing = h.Get("X-User-Owner"), h.Get("X-Billing-Account-Id")
		got.actAsOrg, got.actAsProject = h.Get(iamauth.ActAsOrgHeader), h.Get(iamauth.ActAsProjectHeader)
		c.Status(http.StatusOK)
	}
	r.GET("/v1/x", record)
	r.POST("/v1/sentry/42/envelope/", record) // route class 1: tokenless DSN ingest
	return r, tj, got
}

func call(t *testing.T, r *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestProjectSwitch_MemberHonored: a member of the scope acme/research asks to act
// there and the edge mints it. This is the feature working end to end.
func TestProjectSwitch_MemberHonored(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "acme/research")

	w := call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":            "Bearer " + token,
		iamauth.ActAsProjectHeader: "research",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if got.project != "research" {
		t.Errorf("X-Project-Id = %q, want research — a member switch must be honored", got.project)
	}
	if got.org != "acme" {
		t.Errorf("X-Org-Id = %q, want acme", got.org)
	}
}

// TestProjectSwitch_NonMemberRefused is the core guard: a project the token does NOT
// carry must NEVER be minted. The forged label is what a caller would use to reach
// another tenant's project binding or to evade a project-scoped spend cap, so the
// assertion is not merely "refused" but "the requested value never appears".
func TestProjectSwitch_NonMemberRefused(t *testing.T) {
	r, tj, got := edge(t, nil)
	// alice holds only the org scope — no project grant at all.
	token := scopeToken(t, tj, "acme", "default", "acme")

	w := call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":            "Bearer " + token,
		iamauth.ActAsProjectHeader: "secret",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a refused switch falls back, it does not break the request", w.Code)
	}
	if got.project == "secret" {
		t.Fatal("SECURITY: a non-member project was minted into X-Project-Id from a client header")
	}
	if got.project != "" {
		t.Errorf("X-Project-Id = %q, want \"\" (fail closed to the default scope)", got.project)
	}
}

// TestProjectSwitch_CrossTenantRefused: alice really is a member of victim/secret,
// but she is acting in org acme — the scope is built from the EFFECTIVE org, so the
// grant does not follow her across the tenant boundary (SC-2/AC-4).
func TestProjectSwitch_CrossTenantRefused(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "victim/secret")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":            "Bearer " + token,
		iamauth.ActAsProjectHeader: "secret",
	})
	if got.project != "" {
		t.Fatalf("SECURITY: X-Project-Id = %q — a grant in ANOTHER org must not authorize the same project name in this one", got.project)
	}
	if got.org != "acme" {
		t.Errorf("X-Org-Id = %q, want acme", got.org)
	}
}

// TestProjectSwitch_SameNameDifferentOrgs: two orgs may each have a project named
// "research". Holding acme/research must not authorize beta/research.
func TestProjectSwitch_SameNameDifferentOrgs(t *testing.T) {
	r, tj, got := edge(t, nil)
	// alice may act in org beta (a team) but her ONLY project grant is in acme.
	token := scopeToken(t, tj, "acme", "default", "acme", "acme/research", "beta")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":            "Bearer " + token,
		iamauth.ActAsOrgHeader:     "beta",
		iamauth.ActAsProjectHeader: "research",
	})
	if got.org != "beta" {
		t.Fatalf("X-Org-Id = %q, want beta (the org switch is a valid membership)", got.org)
	}
	if got.project != "" {
		t.Fatalf("SECURITY: X-Project-Id = %q — acme/research must not authorize beta/research", got.project)
	}
}

// TestForgedProjectHeader_NeverSurvives: the MINTED header is not an intent. A client
// copy is stripped at ingress and can never be re-minted from itself — not even when
// the caller genuinely holds a different project.
func TestForgedProjectHeader_NeverSurvives(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "acme/research")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization": "Bearer " + token,
		"X-Project-Id":  "victim-project", // forged: never an input to the mint
	})
	if got.project == "victim-project" {
		t.Fatal("SECURITY: a client-supplied X-Project-Id reached the backend")
	}
	if got.project != "" {
		t.Errorf("X-Project-Id = %q, want \"\" — no switch was REQUESTED, so none is minted", got.project)
	}
}

// TestForgedIdentityHeaders_NeverSurvive proves the strip covers the whole minted set
// on the authed path: every identity header a client sends is replaced by the edge's
// own value or dropped. A forged sub-scope must never be readable by a backend.
func TestForgedIdentityHeaders_NeverSurvive(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":        "Bearer " + token,
		"X-Org-Id":             "victim",
		"X-User-Owner":         "admin", // the platform-sudo predicate
		"X-Project-Id":         "victim-project",
		"X-Billing-Account-Id": "acct_victim",
	})
	if got.org != "acme" {
		t.Errorf("X-Org-Id = %q, want acme (minted from `owner`, never the client's copy)", got.org)
	}
	if got.owner != "acme" {
		t.Errorf("SECURITY: X-User-Owner = %q, want acme — a forged `admin` here is platform sudo", got.owner)
	}
	if got.project != "" {
		t.Errorf("SECURITY: X-Project-Id = %q, want \"\"", got.project)
	}
	if got.billing != "" {
		t.Errorf("SECURITY: X-Billing-Account-Id = %q, want \"\" — the token asserts no account", got.billing)
	}
}

// TestActAsIntent_NeverReachesBackend: an intent is an INPUT to the mint, consumed at
// ingress. It must not reach a backend on ANY route class — including the classes
// that mint no identity at all, where a backend could otherwise read it as a decision
// the edge never made.
func TestActAsIntent_NeverReachesBackend(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "acme/research")

	for _, tc := range []struct {
		name, method, path string
		headers            map[string]string
	}{
		{"authed class, honored switch", http.MethodGet, "/v1/x", map[string]string{
			"Authorization": "Bearer " + token, iamauth.ActAsOrgHeader: "acme", iamauth.ActAsProjectHeader: "research"}},
		{"authed class, refused switch", http.MethodGet, "/v1/x", map[string]string{
			"Authorization": "Bearer " + token, iamauth.ActAsOrgHeader: "victim", iamauth.ActAsProjectHeader: "secret"}},
		// Class 2 short-circuit: an API key mints nothing (the backend authenticates it).
		{"api-key path", http.MethodGet, "/v1/x", map[string]string{
			"Authorization": "Bearer sk-live-abc", iamauth.ActAsOrgHeader: "victim", iamauth.ActAsProjectHeader: "secret"}},
		// Class 1: tokenless DSN ingest mints nothing; cloud resolves the org from the DSN.
		{"tokenless ingest class", http.MethodPost, "/v1/sentry/42/envelope/", map[string]string{
			iamauth.ActAsOrgHeader: "victim", iamauth.ActAsProjectHeader: "secret"}},
	} {
		*got = backend{}
		w := call(t, r, tc.method, tc.path, tc.headers)
		if !got.seen {
			t.Fatalf("%s: request never reached the backend (status %d)", tc.name, w.Code)
		}
		if got.actAsOrg != "" || got.actAsProject != "" {
			t.Errorf("%s: SECURITY: act-as intent reached the backend (org=%q project=%q)",
				tc.name, got.actAsOrg, got.actAsProject)
		}
	}
}

// TestOrgSwitch_NoRegression pins the LIVE org-switch seam through the full
// middleware while the project seam is added beside it: a member switch is honored,
// a non-member fails closed to home, and X-User-Owner stays the home org either way.
func TestOrgSwitch_NoRegression(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "beta-team")

	for _, tc := range []struct {
		name, requested, wantOrg string
	}{
		{"no request → home", "", "acme"},
		{"member team → switch", "beta-team", "beta-team"},
		{"member team, client casing → CANONICAL slug", "Beta-Team", "beta-team"},
		{"non-member → fail closed to home", "victim", "acme"},
	} {
		*got = backend{}
		h := map[string]string{"Authorization": "Bearer " + token}
		if tc.requested != "" {
			h[iamauth.ActAsOrgHeader] = tc.requested
		}
		call(t, r, http.MethodGet, "/v1/x", h)
		if got.org != tc.wantOrg {
			t.Errorf("%s: X-Org-Id = %q, want %q", tc.name, got.org, tc.wantOrg)
		}
		if got.owner != "acme" {
			t.Errorf("%s: X-User-Owner = %q, want acme (home is immutable)", tc.name, got.owner)
		}
	}
}

// TestBillingHint_CannotWidenBillingAuthority: X-Billing-Account-Id is an attribution
// HINT, never a payer decision. The edge's own money check — the balance gate — keys
// on org/user, so a token asserting an account (or a client forging the header) can
// never move the gate onto that account. Commerce resolves the payer at charge time.
//
// The assertion is on the balance query commerce actually RECEIVES, not on a status.
func TestBillingHint_CannotWidenBillingAuthority(t *testing.T) {
	var asked []string
	commerce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("user"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"available": 100.0, "currency": "usd"})
	}))
	defer commerce.Close()

	r, tj, got := edge(t, func(cfg *AuthConfig) {
		cfg.BillingEnabled = true
		cfg.BillingURL = commerce.URL
		cfg.BillingToken = "test-token"
		cfg.BillingPaths = []string{"/v1/x"}
	})

	// A token that ASSERTS a funding account, plus a client forging a different one.
	now := time.Now()
	token := tj.signToken(t, map[string]interface{}{
		"iss": "https://hanzo.id", "sub": "alice", "aud": []string{"https://api.hanzo.ai"},
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"owner": "acme", "billing_account": "acct_asserted",
	})
	w := call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":        "Bearer " + token,
		"X-Billing-Account-Id": "acct_forged",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	// The hint rides as attribution, minted from the CLAIM — never the forged copy.
	if got.billing != "acct_asserted" {
		t.Errorf("X-Billing-Account-Id = %q, want acct_asserted (minted from the claim)", got.billing)
	}
	// The money question the edge asks is keyed on org/user. Neither account appears.
	if len(asked) != 1 {
		t.Fatalf("balance queries = %v, want exactly 1", asked)
	}
	if asked[0] != "acme/alice" {
		t.Fatalf("SECURITY: balance was checked for %q, want acme/alice — a billing-account hint must not move the money check", asked[0])
	}
}

// TestBillingHint_ForgedNeverSurvives: with no `billing_account` claim, a client
// header must not survive to become attribution the edge never asserted.
func TestBillingHint_ForgedNeverSurvives(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":        "Bearer " + token,
		"X-Billing-Account-Id": "acct_victim",
	})
	if got.billing != "" {
		t.Fatalf("SECURITY: X-Billing-Account-Id = %q, want \"\" — the token asserts no account", got.billing)
	}
}

// TestProjectSwitch_DefaultMintsNothing pins the DefaultProject wire contract the
// edge shares with cloud (absent header ⟺ default project): the reserved name is
// org-level and mints nothing, so a switcher can always return to org scope and
// downstream keeps today's un-suffixed keys.
func TestProjectSwitch_DefaultMintsNothing(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "research", "acme", "acme/research")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":            "Bearer " + token,
		iamauth.ActAsProjectHeader: iamauth.DefaultProject,
	})
	if got.project != "" {
		t.Fatalf("X-Project-Id = %q, want \"\" — %q is the org-level scope and mints nothing",
			got.project, iamauth.DefaultProject)
	}
	// Sanity: without the request the claim's own project rides, so the case above is
	// the header doing work rather than the claim being empty.
	*got = backend{}
	call(t, r, http.MethodGet, "/v1/x", map[string]string{"Authorization": "Bearer " + token})
	if got.project != "research" {
		t.Fatalf("baseline X-Project-Id = %q, want research (the `project` claim)", got.project)
	}
}

// TestProjectClaim_DoesNotCrossOrgSwitch: the `project` claim names a project of the
// HOME org. When the caller switches org, minting it would name a project of the
// wrong tenant — which downstream resolves against the NEW org (matching its binding
// or evading its cap). It must be dropped.
func TestProjectClaim_DoesNotCrossOrgSwitch(t *testing.T) {
	r, tj, got := edge(t, nil)
	// alice's home project is acme/research; she is also a member of org beta-team.
	token := scopeToken(t, tj, "acme", "research", "acme", "acme/research", "beta-team")

	call(t, r, http.MethodGet, "/v1/x", map[string]string{
		"Authorization":        "Bearer " + token,
		iamauth.ActAsOrgHeader: "beta-team",
	})
	if got.org != "beta-team" {
		t.Fatalf("X-Org-Id = %q, want beta-team", got.org)
	}
	if got.project != "" {
		t.Fatalf("SECURITY: X-Project-Id = %q under org beta-team — that names acme's project", got.project)
	}
}

// TestScopeSwitch_TableThroughEdge sweeps the predicate through the REAL middleware
// so the header contract and the predicate cannot drift apart.
func TestScopeSwitch_TableThroughEdge(t *testing.T) {
	r, tj, got := edge(t, nil)
	token := scopeToken(t, tj, "acme", "default", "acme", "acme/research", "beta", "beta/labs")

	for _, tc := range []struct {
		name, org, project   string
		wantOrg, wantProject string
	}{
		{"home + member project", "", "research", "acme", "research"},
		{"home + foreign project", "", "labs", "acme", ""},
		{"team + its own project", "beta", "labs", "beta", "labs"},
		{"team + home's project", "beta", "research", "beta", ""},
		{"refused org keeps home, project of home honored", "victim", "research", "acme", "research"},
		{"both refused", "victim", "secret", "acme", ""},
	} {
		*got = backend{}
		h := map[string]string{"Authorization": "Bearer " + token}
		if tc.org != "" {
			h[iamauth.ActAsOrgHeader] = tc.org
		}
		if tc.project != "" {
			h[iamauth.ActAsProjectHeader] = tc.project
		}
		call(t, r, http.MethodGet, "/v1/x", h)
		if got.org != tc.wantOrg || got.project != tc.wantProject {
			t.Errorf("%s: act-as(%q,%q) → (org=%q project=%q), want (org=%q project=%q)",
				tc.name, tc.org, tc.project, got.org, got.project, tc.wantOrg, tc.wantProject)
		}
	}
}
