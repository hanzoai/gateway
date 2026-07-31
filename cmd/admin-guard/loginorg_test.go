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

package main

import "testing"

// The bug these pin, measured live on admin.hanzo.ai before the fix:
//
//	GET / (Accept: text/html)
//	  -> 302 hanzo.id/v1/iam/oauth/authorize?...&organization=hanzo
//
// while the same guard reported adminOrg="admin". authorize() admits a reserved-org
// principal on EVERY host (isPlatformSudo short-circuits before the tenant check),
// so the gate WOULD have taken an `admin/z` session — the browser was simply never
// offered that login. A person who is both admin/z and hanzo/z could therefore never
// obtain the identity the gate was waiting for: it asked for the tenant login, then
// refused the tenant identity for not being platform sudo.

// TestLoginOrgDefaultIsHostDerived pins the PRE-EXISTING behavior, which the fix must
// not change: with no explicit ask, a tenant admin surface still offers that brand's
// org, and an unrecognized host still offers the reserved admin org.
func TestLoginOrgDefaultIsHostDerived(t *testing.T) {
	cfg := &config{adminOrg: "admin"}

	for _, tc := range []struct{ host, want string }{
		{"admin.hanzo.ai", "hanzo"},
		{"admin.lux.cloud", "lux"},
		{"admin.zoo.cloud", "zoo"},
		// Not an admin.<brand> surface -> reserved org (today's global-admin login).
		{"platform.hanzo.ai", "admin"},
		{"cd.hanzo.ai", "admin"},
		{"", "admin"},
	} {
		if got := cfg.loginOrg(tc.host, false); got != tc.want {
			t.Errorf("loginOrg(%q, sudo=false) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// TestLoginOrgSudoReachesTheReservedOrgFromEveryHost is the fix: platform sudo must be
// REACHABLE from a tenant admin surface, or the identity the gate accepts can never be
// presented to it.
func TestLoginOrgSudoReachesTheReservedOrgFromEveryHost(t *testing.T) {
	cfg := &config{adminOrg: "admin"}

	for _, host := range []string{"admin.hanzo.ai", "admin.lux.cloud", "platform.hanzo.ai", "", "nope.example"} {
		if got := cfg.loginOrg(host, true); got != "admin" {
			t.Errorf("loginOrg(%q, sudo=true) = %q, want the reserved org %q", host, got, "admin")
		}
	}
}

// TestSudoRequestedIsExact keeps the trigger unambiguous. A stray `sudo=0` or a bare
// `sudo=` must NOT steer someone to a login their host did not intend — the default
// has to stay the default unless it was actually asked for.
func TestSudoRequestedIsExact(t *testing.T) {
	for _, q := range []string{"sudo=1", "next=%2Forgs&sudo=1", "sudo=1&x=y"} {
		if !sudoRequested(q) {
			t.Errorf("sudoRequested(%q) = false, want true", q)
		}
	}
	for _, q := range []string{"", "sudo=0", "sudo=", "sudo", "sudo=true", "nosudo=1", "presudo=1", "x=sudo=1"} {
		if sudoRequested(q) {
			t.Errorf("sudoRequested(%q) = true, want false", q)
		}
	}
}

// TestAskingForSudoDoesNotGrantIt is the security property the whole change rests on.
// The org hint only decides which login is OFFERED; handleCallback re-runs authorize()
// before minting a session, so a principal that is not in the reserved org is refused
// on a global surface no matter what it asked for. If this ever fails, the query param
// has become an escalation and must be removed.
func TestAskingForSudoDoesNotGrantIt(t *testing.T) {
	cfg := &config{adminOrg: "admin"}

	// An unrecognized host has no tenant org, so authorize() admits ONLY platform sudo.
	const globalHost = "platform.hanzo.ai"

	tenantAdmin := principal{owner: "hanzo", isAdmin: true}
	if cfg.authorize(tenantAdmin, globalHost) {
		t.Error("a tenant admin was authorized on a global surface — asking for sudo must not confer it")
	}

	anon := principal{}
	if cfg.authorize(anon, globalHost) {
		t.Error("an anonymous principal was authorized on a global surface")
	}

	// And the reserved-org principal — the one the sudo login exists to produce — is
	// admitted, on the tenant surface too (isPlatformSudo short-circuits every host).
	sudo := principal{owner: "admin", isAdmin: true}
	for _, host := range []string{globalHost, "admin.hanzo.ai"} {
		if !cfg.authorize(sudo, host) {
			t.Errorf("reserved-org principal was refused on %q — the gate must accept the identity it offers", host)
		}
	}
}
