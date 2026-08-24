// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package iam names the addresses Hanzo IAM answers on.
//
// Three binaries in this module read identity from IAM — the admin guard, the
// waitlist guard and the admin API — and each used to spell the addresses in its
// own string literal. An address that lives in three places is an address that
// can be checked in none: when IAM retired the verb-noun spellings, every one of
// those literals kept compiling and started answering 410, and a guard reads a
// 410 as "not this person".
//
// So the address is a VALUE with one home. A caller says which resource it wants;
// where that resource lives is stated here once.
//
// Two conventions live behind these addresses and a reader has to know which it
// is holding. [Account] answers the envelope — `{"status":"ok","data":{…}}`, and
// a refusal is HTTP 200 carrying `{"status":"error"}`, so the STATUS CODE ALONE
// NEVER DECIDES a caller's verdict there. Everything else is typed CRUD: the body
// IS the record or the list, and a refusal is a real 4xx carrying an RFC 9457
// problem document.
package iam

import (
	"net/url"
	"strings"
)

// The resource addresses. Each one is a collection except [Account], which is the
// calling person themselves.
const (
	// Account is the signed-in caller's own record, resolved from the credential
	// on the request. Envelope convention — see the package comment.
	Account = "/v1/iam/account"

	// Users is the people in one organization. `owner` is REQUIRED; `email`
	// narrows the page to one address; `limit` and `offset` page it. There is no
	// ownerless listing, so a caller that wants every tenant's people asks
	// [Organizations] first and reads each one.
	Users = "/v1/iam/users"

	// Organizations is the tenants the caller may act in, paged by `cursor`.
	Organizations = "/v1/iam/organizations"

	// Applications, Roles and AuditLogs are each scoped by `owner`.
	Applications = "/v1/iam/applications"
	Roles        = "/v1/iam/roles"
	AuditLogs    = "/v1/iam/audit-logs"
)

// User is the address of one person's record, addressed by the natural key IAM
// writes as "owner/name".
//
// It returns "" for anything that is not exactly two non-empty segments. A caller
// holding half an identifier has not named a person, and building a URL out of it
// would address the COLLECTION instead — which answers 200 with a list, and a
// reader looking for one record would take the first thing in it. Refusing here
// is what keeps a malformed identifier a denial rather than a wrong person.
func User(id string) string {
	owner, name, ok := strings.Cut(id, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return ""
	}
	return Users + "/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}
