package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The login hint has to agree with the policy the surface is gated by, and it
// did not. o11y.hanzo.ai is wired to verify-authn precisely so that an ordinary
// org member can open Observe and see their OWN telemetry — but the hint fell
// through to the reserved admin org, and IAM refuses an authorize whose resolved
// user is not in the pinned org ("federation is not permitted for this
// application"). So an admits-anyone surface was admin-ONLY: the exact
// platform-sudo gate choosing verify-authn was meant to avoid.
//
// Measured live on o11y.hanzo.ai before the fix: the guard sent
// organization=admin, and signing in as z@hanzo.ai (which resolves to hanzo/z)
// came back to /__guard/callback with error=access_denied and that description.
func TestAuthnSurfacePinsNoLoginOrg(t *testing.T) {
	c := &config{adminOrg: "admin"}

	// The surfaces actually wired to o11y-guard.
	for _, host := range []string{"o11y.hanzo.ai", "obs.hanzo.ai"} {
		if got := c.loginOrg(host, authnPolicy); got != "" {
			t.Errorf("loginOrg(%q, authn) = %q, want \"\" — pinning an org on a "+
				"surface whose policy admits any principal makes it admin-only, "+
				"because IAM refuses a cross-org authorize", host, got)
		}
	}
}

// Pinning the host's BRAND org would have been the tempting fix and is the wrong
// one: it only moves the exclusion onto the global admins who are the only people
// who can reach the surface today. Both are legitimate users of an authn surface,
// so the hint must name neither.
func TestAuthnSurfaceDoesNotPinTheBrandEither(t *testing.T) {
	c := &config{adminOrg: "admin"}
	if got := c.loginOrg("o11y.hanzo.ai", authnPolicy); got == "hanzo" {
		t.Fatalf("loginOrg pinned the brand org %q — that trades one lockout for "+
			"another rather than removing it", got)
	}
}

// The admin policy is UNCHANGED. A tenant admin surface still authenticates into
// its own brand org, and every global/DO-infra surface still pins the reserved
// admin org — that is what preserves the global-admin login on platform.hanzo.ai.
func TestAdminPolicyLoginOrgIsUnchanged(t *testing.T) {
	c := &config{adminOrg: "admin"}
	for _, tc := range []struct{ host, want string }{
		{"admin.hanzo.ai", "hanzo"},
		{"admin.lux.cloud", "lux"},
		{"admin.zoo.cloud", "zoo"},
		{"platform.hanzo.ai", "admin"},
		{"studio.hanzo.ai", "admin"},
		{"hanzo.ai", "admin"},
		{"something.unrecognized.example", "admin"},
	} {
		if got := c.loginOrg(tc.host, adminPolicy); got != tc.want {
			t.Errorf("loginOrg(%q, admin) = %q, want %q", tc.host, got, tc.want)
		}
	}
	// A tenant admin host keeps its brand org under EITHER policy — the host is
	// the stronger statement there, and it is derived solely from the trusted
	// ingress-set host.
	if got := c.loginOrg("admin.hanzo.ai", authnPolicy); got != "hanzo" {
		t.Errorf("loginOrg(admin.hanzo.ai, authn) = %q, want hanzo", got)
	}
}

// An empty hint must be OMITTED, not sent as `organization=`. A stated-and-empty
// org is a different request from no org at all: it hands IAM a value to resolve
// on a field the caller never meant to constrain.
func TestEmptyLoginOrgIsOmittedFromAuthorizeURL(t *testing.T) {
	c := &config{adminOrg: "admin"}
	host := "o11y.hanzo.ai"

	q := url.Values{}
	if org := c.loginOrg(host, authnPolicy); org != "" {
		q.Set("organization", org)
	}
	if _, present := q["organization"]; present {
		t.Fatalf("authorize query carries organization=%q; an authn surface must "+
			"send no organization at all", q.Get("organization"))
	}
	if strings.Contains(q.Encode(), "organization") {
		t.Fatalf("encoded query still mentions organization: %s", q.Encode())
	}
}

// A refused authorize comes back to the callback as `error`, not `code` — so the
// no-code path is the shape a REFUSAL takes. It used to report "missing
// code/state", which tells an operator their request was malformed when IAM had
// answered them in words about their identity.
func TestCallbackReportsTheRefusalItWasGiven(t *testing.T) {
	c := &config{adminOrg: "admin"}

	r := httptest.NewRequest("GET", "/__guard/callback?error=access_denied"+
		"&error_description=federation+is+not+permitted+for+this+application"+
		"&state=abc", nil)
	w := httptest.NewRecorder()
	c.handleCallback(w, r)

	body := w.Body.String()
	if w.Code == 400 && strings.Contains(body, "missing code/state") {
		t.Fatal("callback reported a parameter complaint for an authorization " +
			"refusal — the reason IAM gave was discarded")
	}
	for _, want := range []string{"access_denied", "federation is not permitted"} {
		if !strings.Contains(body, want) {
			t.Errorf("callback body %q does not carry %q", body, want)
		}
	}
	if w.Code != 403 {
		t.Errorf("status = %d, want 403 for a refused sign-in", w.Code)
	}
}

// A genuinely malformed callback — no error, no code — still reports itself as
// malformed. The new branch must not swallow that case.
func TestCallbackStillReportsAMalformedRequest(t *testing.T) {
	c := &config{adminOrg: "admin"}
	r := httptest.NewRequest("GET", "/__guard/callback", nil)
	w := httptest.NewRecorder()
	c.handleCallback(w, r)

	if w.Code != 400 || !strings.Contains(w.Body.String(), "missing code/state") {
		t.Fatalf("got %d %q, want 400 missing code/state", w.Code, w.Body.String())
	}
}
