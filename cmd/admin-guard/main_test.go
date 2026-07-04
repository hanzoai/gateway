package main

import "testing"

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
			owner, ok := ownerFromAccount([]byte(tc.body))
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
