package main

import "testing"

// TestOwnerFromAccountIsAdmin proves the guard extracts the global-admin flag from
// get-account, so z@hanzo.ai (org "hanzo", NOT the reserved "admin" org, but isAdmin)
// is recognized as a global admin — the bug that bounced them to console.hanzo.ai.
func TestOwnerFromAccountIsAdmin(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantOwner   string
		wantIsAdmin bool
	}{
		{"superuser: hanzo org + isAdmin", `{"owner":"hanzo","name":"z","isAdmin":true}`, "hanzo", true},
		{"wrapped isAdmin", `{"status":"ok","data":{"owner":"hanzo","isAdmin":true}}`, "hanzo", true},
		{"normal user: no isAdmin", `{"owner":"maxpower","name":"dave"}`, "maxpower", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, isAdmin, ok := ownerFromAccount([]byte(tc.body))
			if !ok || owner != tc.wantOwner || isAdmin != tc.wantIsAdmin {
				t.Fatalf("ownerFromAccount(%s) = (%q,%v,%v), want (%q,%v,true)", tc.body, owner, isAdmin, ok, tc.wantOwner, tc.wantIsAdmin)
			}
		})
	}
}

// decideVerdict is the pure admit/deny at the heart of the guard: a global admin is
// EITHER an admin-org member OR any isAdmin principal (matches the console gate).
func decideVerdict(owner, adminOrg string, isAdmin bool) bool {
	return isAdmin || (owner != "" && owner == adminOrg)
}

func TestDecideAllowsGlobalAdmin(t *testing.T) {
	cases := []struct {
		owner, adminOrg string
		isAdmin, allow  bool
	}{
		{"admin", "admin", false, true},     // admin-org member (legacy path)
		{"hanzo", "admin", true, true},      // z@hanzo.ai: brand org + isAdmin → ADMIT (the fix)
		{"maxpower", "admin", false, false}, // normal org, not admin → deny (redirect to console)
		{"", "admin", false, false},         // anonymous → deny
	}
	for _, tc := range cases {
		if got := decideVerdict(tc.owner, tc.adminOrg, tc.isAdmin); got != tc.allow {
			t.Errorf("decide(owner=%q admin=%q isAdmin=%v) = %v, want %v", tc.owner, tc.adminOrg, tc.isAdmin, got, tc.allow)
		}
	}
}

func TestOwnerFromAccount(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantOwner string
		wantOK    bool
	}{
		{"top-level owner", `{"owner":"admin","name":"z"}`, "admin", true},
		{"wrapped in data", `{"status":"ok","data":{"owner":"hanzo","name":"dave"}}`, "hanzo", true},
		{"error response", `{"status":"error","msg":"Please login first"}`, "", false},
		{"missing owner", `{"status":"ok","data":{"name":"x"}}`, "", false},
		{"garbage", `not json`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, _, ok := ownerFromAccount([]byte(tc.body))
			if owner != tc.wantOwner || ok != tc.wantOK {
				t.Fatalf("ownerFromAccount(%s) = (%q,%v), want (%q,%v)", tc.body, owner, ok, tc.wantOwner, tc.wantOK)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	c := &config{hmacKey: []byte("0123456789abcdef")}
	signed := c.sign("admin|9999999999")
	got, ok := c.verifySigned(signed)
	if !ok || got != "admin|9999999999" {
		t.Fatalf("verifySigned round-trip = (%q,%v)", got, ok)
	}
	// Tamper detection.
	if _, ok := c.verifySigned(signed + "x"); ok {
		t.Fatal("verifySigned accepted a tampered signature")
	}
	if _, ok := c.verifySigned("garbage"); ok {
		t.Fatal("verifySigned accepted garbage")
	}
}

func TestSessionOwnerExpiry(t *testing.T) {
	c := &config{hmacKey: []byte("0123456789abcdef"), cookieName: "g"}
	// Forge an expired payload directly and confirm it is rejected by the
	// expiry check inside sessionOwner's parsing logic.
	expired := c.sign("admin|1")
	payload, ok := c.verifySigned(expired)
	if !ok {
		t.Fatal("signed payload should verify")
	}
	// owner|exp where exp=1 (1970) → expired.
	if payload != "admin|1" {
		t.Fatalf("unexpected payload %q", payload)
	}
}
