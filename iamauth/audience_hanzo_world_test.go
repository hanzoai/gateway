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

// TestDefaultAudiences_AcceptsHanzoWorld pins the world.hanzo.ai OIDC client.
// IAM mints world's access tokens with aud=hanzo-world (each app's aud is its
// client_id). Those bearers hit the AI gateway; if hanzo-world is not an accepted
// audience the token is rejected, the request resolves anonymous, and the signed-in
// analyst's api.hanzo.ai calls 401. Pin the client_id into the baked allowlist.
func TestDefaultAudiences_AcceptsHanzoWorld(t *testing.T) {
	found := false
	for _, a := range DefaultAudiences {
		if a == "hanzo-world" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DefaultAudiences must include hanzo-world (the world.hanzo.ai client_id); got %v", DefaultAudiences)
	}

	// End-to-end: a token whose aud is hanzo-world validates against the baked
	// default allowlist (the exact audience IAM stamps for that client).
	ts := newTestSigner(t)
	srv := ts.serveJWKS(t)
	defer srv.Close()
	cache := NewJWKSCache(srv.URL, time.Minute)

	tok := ts.sign(t, testIssuer, "hanzo-world")
	if _, err := ValidateToken(tok, cache, testIssuer, DefaultAudiences); err != nil {
		t.Fatalf("aud=hanzo-world must validate against DefaultAudiences, got: %v", err)
	}
}
