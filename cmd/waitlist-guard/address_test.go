// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/gateway/v2/iam"
)

// record answers every request with body and remembers the address it was asked
// for, so a test can assert WHERE the guard went as well as what it concluded.
func record(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	asked := new(string)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*asked = r.URL.RequestURI()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s, asked
}

// The session path reads the account at the address IAM serves.
func TestSessionApprovalAsksTheAccountAddress(t *testing.T) {
	idp, asked := record(t, 200, `{"status":"ok","data":{"owner":"hanzo","name":"alice"}}`)
	c := newTestConfig(idp.URL, false)

	owner, approved, outcome := c.iamSessionApproval(browserReq())
	if outcome != iamOK || owner != "hanzo" || !approved {
		t.Fatalf("account read: owner=%q approved=%v outcome=%v", owner, approved, outcome)
	}
	if *asked != iam.Account {
		t.Fatalf("guard asked %q, want %q", *asked, iam.Account)
	}
}

// A person's approval is read from their RECORD — the item address, with both
// halves of the natural key in the path. It is not a query over the collection:
// the collection answers 200 with a list, and this reader takes what it is given
// as one person.
func TestUserApprovedAsksTheRecordAddress(t *testing.T) {
	idp, asked := record(t, 200, `{"owner":"hanzo","name":"alice"}`)
	c := newTestConfig(idp.URL, false)

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	approved, outcome := c.iamUserApproved(r, "hanzo/alice")
	if outcome != iamOK || !approved {
		t.Fatalf("record read: approved=%v outcome=%v", approved, outcome)
	}
	if want := iam.User("hanzo/alice"); *asked != want {
		t.Fatalf("guard asked %q, want %q", *asked, want)
	}
}

// The bearer variant addresses the same record.
func TestUserApprovedBearerAsksTheRecordAddress(t *testing.T) {
	idp, asked := record(t, 200, `{"owner":"hanzo","name":"alice"}`)
	c := newTestConfig(idp.URL, false)

	if !c.getUserApprovedBearer(context.Background(), "hanzo/alice", "tok") {
		t.Fatal("bearer record read did not approve an approved person")
	}
	if want := iam.User("hanzo/alice"); *asked != want {
		t.Fatalf("guard asked %q, want %q", *asked, want)
	}
}

// A RETIRED ADDRESS IS A DENIAL, NEVER AN ADMISSION. 410 is a 4xx: definitive,
// so it is iamDenied and not the iamUnavailable that a validated JWT is allowed
// to ride through. If this ever reports iamUnavailable, the waitlist opens to
// everyone holding a token the moment an address is retired.
func TestRetiredAddressDenies(t *testing.T) {
	idp, _ := record(t, http.StatusGone, `{"successor":["/v1/iam/users"]}`)
	c := newTestConfig(idp.URL, true) // fail-open ON: the outcome must still deny

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	if approved, outcome := c.iamUserApproved(r, "hanzo/alice"); approved || outcome != iamDenied {
		t.Fatalf("410 gave approved=%v outcome=%v, want false/iamDenied", approved, outcome)
	}
	if _, _, outcome := c.iamSessionApproval(browserReq()); outcome != iamDenied {
		t.Fatalf("410 on the account read gave outcome=%v, want iamDenied", outcome)
	}
	if c.getUserApprovedBearer(context.Background(), "hanzo/alice", "tok") {
		t.Fatal("410 approved a person on the bearer path")
	}
}

// An id that does not name exactly one person yields no address at all, so the
// guard denies without a request. Building Users+"/"+half would address the
// COLLECTION, which answers 200 — and this reader would take the page for a
// person and read an approval off it.
func TestHalfAnIdentifierDeniesWithoutAsking(t *testing.T) {
	asked := false
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked = true
		_, _ = w.Write([]byte(`{"owner":"hanzo","name":"alice"}`))
	}))
	defer idp.Close()
	c := newTestConfig(idp.URL, true)

	r := httptest.NewRequest(http.MethodGet, "/__guard/verify", nil)
	for _, id := range []string{"", "/", "hanzo", "hanzo/", "/alice"} {
		if approved, outcome := c.iamUserApproved(r, id); approved || outcome != iamDenied {
			t.Fatalf("id %q gave approved=%v outcome=%v, want false/iamDenied", id, approved, outcome)
		}
		if c.getUserApprovedBearer(context.Background(), id, "tok") {
			t.Fatalf("id %q approved on the bearer path", id)
		}
	}
	if asked {
		t.Fatal("guard sent a request for an id that names no person")
	}
}

// The account read answers a REFUSAL AT HTTP 200, so the status code alone never
// decides. Only the envelope does.
func TestAccountRefusalAt200Denies(t *testing.T) {
	idp, _ := record(t, 200, `{"status":"error","msg":"please sign in first"}`)
	c := newTestConfig(idp.URL, true)

	if _, _, outcome := c.iamSessionApproval(browserReq()); outcome != iamDenied {
		t.Fatalf("a 200 refusal gave outcome=%v, want iamDenied", outcome)
	}
}
