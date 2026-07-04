// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamauth

import (
	"testing"
	"time"
)

// TestDefaultAudiences_AcceptsAdminGuard is the operator-cockpit keystone.
// The admin.hanzo.ai forward-auth guard is the confidential client
// `hanzo-admin-guard`, so IAM mints its access tokens with aud=hanzo-admin-guard
// (each app's aud is its client_id). The guard forwards that bearer to /v1/admin/*
// behind this gateway; if hanzo-admin-guard is not an accepted audience the token
// is rejected, the request resolves anonymous, and the SuperAdmin `owner==admin`
// gate reads false -> 403, even though the token's owner IS admin. Pin the
// client_id into the baked allowlist so the forwarded bearer validates and the
// cockpit renders.
func TestDefaultAudiences_AcceptsAdminGuard(t *testing.T) {
	found := false
	for _, a := range DefaultAudiences {
		if a == "hanzo-admin-guard" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DefaultAudiences must include hanzo-admin-guard (the admin-cockpit guard client_id); got %v", DefaultAudiences)
	}

	// End-to-end: a token whose aud is hanzo-admin-guard validates against the
	// baked default allowlist (the exact audience IAM stamps for that client).
	ts := newTestSigner(t)
	srv := ts.serveJWKS(t)
	defer srv.Close()
	cache := NewJWKSCache(srv.URL, time.Minute)

	tok := ts.sign(t, testIssuer, "hanzo-admin-guard")
	if _, err := ValidateToken(tok, cache, testIssuer, DefaultAudiences); err != nil {
		t.Fatalf("aud=hanzo-admin-guard must validate against DefaultAudiences, got: %v", err)
	}
}
