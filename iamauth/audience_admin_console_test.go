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

// TestDefaultAudiences_AcceptsAdminConsole is the SUPERADMIN-operator keystone.
//
// A platform SuperAdmin signs in through the admin console (admin.hanzo.ai), whose
// OIDC client is `admin-console`. IAM stamps that login's access token with
// aud=admin-console (each app's aud is its client_id) and owner=admin. The `hanzo`
// CLI forwards that bearer to the platform surface (platform.hanzo.ai/v1/paas/*)
// through THIS gateway — the hanzoai/ingress edge embeds this validator. If
// admin-console is not an accepted audience the edge rejects the token 401 (invalid
// audience claim) BEFORE it reaches cloud, so a superadmin can never drive a deploy
// even though cloud itself already trusts admin-console. The sibling client
// hanzo-admin-guard is already pinned; admin-console is the console's OWN client and
// must be trusted the same way, or the two admin surfaces disagree.
//
// This mirrors cloud's own fix (hanzoai/cloud defaultJWTAudiences += admin-console)
// so the edge and the in-binary validator agree on the one admin-org audience set.
func TestDefaultAudiences_AcceptsAdminConsole(t *testing.T) {
	found := false
	for _, a := range DefaultAudiences {
		if a == "admin-console" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DefaultAudiences must include admin-console (the admin-console OIDC client_id; superadmin login mints aud=admin-console); got %v", DefaultAudiences)
	}

	// End-to-end: a token whose aud is admin-console validates against the baked
	// default allowlist (the exact audience IAM stamps for the admin-console client).
	ts := newTestSigner(t)
	srv := ts.serveJWKS(t)
	defer srv.Close()
	cache := NewJWKSCache(srv.URL, time.Minute)

	tok := ts.sign(t, testIssuer, "admin-console")
	if _, err := ValidateToken(tok, cache, testIssuer, DefaultAudiences); err != nil {
		t.Fatalf("aud=admin-console must validate against DefaultAudiences, got: %v", err)
	}
}
