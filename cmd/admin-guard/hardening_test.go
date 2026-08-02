package main

// DEFENCE IN DEPTH AT THE GUARD'S OWN EDGE.
//
// The guard's __guard/* endpoints are the only part of it a client can address
// directly, and they answer before any identity exists. Three properties of that
// pre-auth surface are pinned here.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The public probe says whether the guard is up. It must not also say which
// guard it is: a version on an unauthenticated endpoint on every guarded host
// turns "find a host running a build with a known issue" into one GET.
func TestHealthzDoesNotDiscloseTheBuild(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler()(rec, httptest.NewRequest(http.MethodGet, healthPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, guardVersion) {
		t.Errorf("healthz body %q carries the build %q — an unauthenticated probe on "+
			"every guarded host should not name the version it is running", body, guardVersion)
	}
}

// returnTo is where a browser lands after a successful login. It arrives inside
// the HMAC-signed state, so it is a fact the guard told itself — but what the
// guard told itself came from X-Forwarded-Host, and "starts with https://" is not
// a statement about WHICH host. Pin it to the host being guarded, so the check
// constrains the destination rather than the scheme.
func TestReturnToIsPinnedToTheGuardedHost(t *testing.T) {
	c := testConfig()
	r := httptest.NewRequest(http.MethodGet, callbackPath, nil)
	r.Header.Set("X-Forwarded-Host", "o11y.hanzo.ai")

	cases := []struct {
		name, returnTo string
		want           bool
	}{
		{"same host", "https://o11y.hanzo.ai/services", true},
		{"same host, root", "https://o11y.hanzo.ai/", true},
		{"foreign host", "https://evil.example/steal", false},
		{"lookalike prefix", "https://o11y.hanzo.ai.evil.example/x", false},
		{"userinfo trick", "https://evil.example/@o11y.hanzo.ai/", false},
		{"scheme-relative", "//evil.example/x", false},
		{"plain http on the same host", "http://o11y.hanzo.ai/x", false},
		{"empty", "", false},
		{"backslash confusion", "https://o11y.hanzo.ai\\@evil.example/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.returnToAllowed(r, tc.returnTo); got != tc.want {
				t.Errorf("returnToAllowed(%q) = %v, want %v", tc.returnTo, got, tc.want)
			}
		})
	}
}

// A cookie the guard cannot possibly have issued must not cost an IAM
// round-trip. The pre-auth path is unthrottled by design (it is the login path),
// so the work each unauthenticated request can compel has to be bounded at the
// guard rather than at the ingress.
func TestIAMLookupIsBoundedForUnauthenticatedCallers(t *testing.T) {
	if iamLookupTimeout > maxIAMLookupTimeout {
		t.Errorf("iamLookupTimeout = %v, want <= %v — every anonymous request with any "+
			"Cookie header holds a guard goroutine and connection for this long",
			iamLookupTimeout, maxIAMLookupTimeout)
	}
	if iamLookupInFlight <= 0 {
		t.Fatal("iamLookupInFlight must bound the concurrent pre-auth IAM round-trips")
	}

	// The limiter admits up to its bound and refuses beyond it, so a flood cannot
	// occupy every worker.
	gate := newInFlightGate(2)
	if !gate.enter() || !gate.enter() {
		t.Fatal("gate refused a caller within its bound")
	}
	if gate.enter() {
		t.Error("gate admitted a caller beyond its bound — the pre-auth IAM path is unbounded")
	}
	gate.leave()
	if !gate.enter() {
		t.Error("gate did not release a slot on leave")
	}
}
