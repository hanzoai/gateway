// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestApprovalFromAccount locks the gate's core predicate. It MUST fail-OPEN for
// existing users (no property ⇒ approved), gate only an explicit "pending", treat
// admins (owner==adminOrg or isAdmin) as always approved, parse both the top-level
// and data-wrapped IAM shapes, and reject an error/ownerless body.
func TestApprovalFromAccount(t *testing.T) {
	const adminOrg = "admin"
	cases := []struct {
		name         string
		body         string
		wantOwner    string
		wantApproved bool
		wantOK       bool
	}{
		{"error body", `{"status":"error","msg":"nope"}`, "", false, false},
		{"empty owner", `{"status":"ok"}`, "", false, false},
		{"existing user no props -> approved (fail-open)", `{"owner":"hanzo","name":"a"}`, "hanzo", true, true},
		{"explicit approved", `{"owner":"hanzo","properties":{"approvalStatus":"approved"}}`, "hanzo", true, true},
		{"explicit pending -> gated", `{"owner":"hanzo","properties":{"approvalStatus":"pending"}}`, "hanzo", false, true},
		{"rejected (not pending) -> approved-by-fallthrough", `{"owner":"hanzo","properties":{"approvalStatus":"rejected"}}`, "hanzo", true, true},
		{"pending but global admin -> approved", `{"owner":"admin","properties":{"approvalStatus":"pending"}}`, "admin", true, true},
		{"pending but isAdmin -> approved", `{"owner":"hanzo","isAdmin":true,"properties":{"approvalStatus":"pending"}}`, "hanzo", true, true},
		{"data-wrapped pending", `{"status":"ok","data":{"owner":"hanzo","properties":{"approvalStatus":"pending"}}}`, "hanzo", false, true},
		{"data-wrapped existing -> approved", `{"status":"ok","data":{"owner":"zoo","name":"b"}}`, "zoo", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, approved, ok := approvalFromAccount([]byte(tc.body), adminOrg)
			if owner != tc.wantOwner || approved != tc.wantApproved || ok != tc.wantOK {
				t.Fatalf("approvalFromAccount(%s) = (%q,%v,%v); want (%q,%v,%v)",
					tc.body, owner, approved, ok, tc.wantOwner, tc.wantApproved, tc.wantOK)
			}
		})
	}
}

// TestSessionForgeryRejected verifies the signed session cookie is tamper-evident:
// an attacker who flips the approved bit (0→1) in the cleartext half while keeping
// the original MAC is REJECTED. The gate must never trust a forged approved bit.
func TestSessionForgeryRejected(t *testing.T) {
	c := &config{hmacKey: []byte("0123456789abcdef0123456789abcdef")}

	// Legit unapproved session, signed correctly.
	unapproved := "hanzo|0|9999999999"
	signed := c.sign(unapproved)
	if got, ok := c.verifySigned(signed); !ok || got != unapproved {
		t.Fatalf("round-trip failed: ok=%v got=%q", ok, got)
	}

	// Attacker rewrites ONLY the base64(payload) half to say approved=1, reusing
	// the original MAC (base64(mac)). verifySigned must reject it.
	_, macB64, _ := strings.Cut(signed, ".")
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte("hanzo|1|9999999999"))
	forged := forgedPayload + "." + macB64
	if _, ok := c.verifySigned(forged); ok {
		t.Fatal("verifySigned ACCEPTED a forged approved bit — the gate is bypassable")
	}
}
