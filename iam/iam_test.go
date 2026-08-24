// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package iam

import "testing"

// A person's record is addressed by BOTH halves of the natural key or not at
// all. The danger is not a 404 — it is that Users+"/"+half addresses the
// COLLECTION, which answers 200 with a list, and every caller here reads the
// answer as one person.
func TestUserRefusesHalfAnIdentifier(t *testing.T) {
	for _, id := range []string{
		"",               // nothing
		"/",              // both halves empty
		"hanzo",          // no name
		"hanzo/",         // empty name
		"/alice",         // empty owner
		"a/b/c",          // not a natural key
		"hanzo//bob",     // empty middle segment
		"hanzo/../admin", // a traversal is three segments, not a name
	} {
		if got := User(id); got != "" {
			t.Errorf("User(%q) = %q, want \"\" — a half identifier must yield no address", id, got)
		}
	}
}

// The address is the collection plus the two segments, each escaped, so a name
// carrying a slash or a space cannot reach a different route.
func TestUserAddressesOnePerson(t *testing.T) {
	for _, tc := range []struct{ id, want string }{
		{"hanzo/alice", "/v1/iam/users/hanzo/alice"},
		{"hanzo/a b", "/v1/iam/users/hanzo/a%20b"},
		{"hanzo/a.b", "/v1/iam/users/hanzo/a.b"},
	} {
		if got := User(tc.id); got != tc.want {
			t.Errorf("User(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

// The addresses IAM actually serves. A literal here is the point: if one of
// these constants is edited to an address IAM retired, this test says so.
func TestAddressesAreTheServedOnes(t *testing.T) {
	for name, got := range map[string]string{
		"Account":       Account,
		"Users":         Users,
		"Organizations": Organizations,
		"Applications":  Applications,
		"Roles":         Roles,
		"AuditLogs":     AuditLogs,
	} {
		want := map[string]string{
			"Account":       "/v1/iam/account",
			"Users":         "/v1/iam/users",
			"Organizations": "/v1/iam/organizations",
			"Applications":  "/v1/iam/applications",
			"Roles":         "/v1/iam/roles",
			"AuditLogs":     "/v1/iam/audit-logs",
		}[name]
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
