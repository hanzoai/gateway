// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/gateway/v2/iam"
)

// The session path asks IAM for the account at the address IAM serves, and asks
// for nothing else. A fixture that answered whatever it was asked is how the
// retired spelling survived a green suite while production answered 410.
func TestSessionPrincipalAsksTheAccountAddress(t *testing.T) {
	var asked string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write([]byte(`{"status":"ok","sub":"admin/root","data":{"owner":"admin","name":"root","isAdmin":true}}`))
	}))
	defer idp.Close()

	c := testConfig()
	c.iamInternal = idp.URL
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "hanzo_session=abc")

	p, ok := c.iamSessionPrincipal(r)
	if !ok || p.owner != "admin" {
		t.Fatalf("account read did not resolve the principal: ok=%v owner=%q", ok, p.owner)
	}
	if asked != iam.Account {
		t.Fatalf("guard asked %q, want %q", asked, iam.Account)
	}
}

// Every answer that is not a signed-in person must yield NO principal.
//
// The two that matter are at the top. A retired address answers 410, and a guard
// that read a 410 as anything but "no principal" would admit on an address that
// no longer exists. And the account read answers a REFUSAL AT HTTP 200 — so the
// status code alone never decides here, the envelope does. A reader that trusted
// the status would take `{"status":"error"}` for a principal with an empty owner.
func TestSessionPrincipalFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"retired address answers 410", http.StatusGone, `{"successor":["/v1/iam/account"]}`},
		{"refusal rides on 200", http.StatusOK, `{"status":"error","msg":"please sign in first"}`},
		{"unauthorized", http.StatusUnauthorized, `{"status":401,"title":"Unauthorized"}`},
		{"server error", http.StatusInternalServerError, `{"status":"error","msg":"server_error"}`},
		{"ok but nobody", http.StatusOK, `{"status":"ok","data":{}}`},
		{"ok but no owner", http.StatusOK, `{"status":"ok","data":{"name":"root","isAdmin":true}}`},
		{"not json", http.StatusOK, `<html>login</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer idp.Close()

			c := testConfig()
			c.iamInternal = idp.URL
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Cookie", "hanzo_session=abc")

			if p, ok := c.iamSessionPrincipal(r); ok {
				t.Fatalf("admitted on %s: principal=%+v", tc.name, p)
			}
		})
	}
}
