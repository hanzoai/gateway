// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	koanf "github.com/hanzoai/gateway/v2/internal/plugin/koanf"
)

// AUTH_ENABLED has one off position and every other string leaves the policy
// in force. Both transports read it through authEnabled, so this table is the
// whole contract for both.
func TestAuthEnabled(t *testing.T) {
	for _, c := range []struct {
		value string
		want  bool
	}{
		{"false", false},
		{"False", false},
		{"FALSE", false},
		{" false ", false},
		{"", true},
		{"true", true},
		{"1", true},
		{"0", true},
		{"no", true},
		{"off", true},
		{"flase", true},
		{"false ish", true},
	} {
		t.Setenv("AUTH_ENABLED", c.value)
		if got := authEnabled(); got != c.want {
			t.Errorf("AUTH_ENABLED=%q: authEnabled() = %v, want %v", c.value, got, c.want)
		}
	}
}

// The two transports build their AuthConfig by different routes. They must
// reach the same answer from the same value, or the looser one is the policy.
func TestAuthEnabledAgreesAcrossTransports(t *testing.T) {
	for _, value := range []string{"", "true", "false", "0", "TRUE", "yes"} {
		t.Setenv("AUTH_ENABLED", value)
		zip := authConfigFromEnv(MountDeps{Domain: "hanzo.ai"}).Enabled
		gin := DefaultAuthConfig().Enabled
		if zip != gin {
			t.Errorf("AUTH_ENABLED=%q: zip transport Enabled=%v, gin transport Enabled=%v", value, zip, gin)
		}
	}
}

// ─── What the CONFIG states ─────────────────────────────────────────────────

// liveShape is a gateway.json in the shape production mounts: KrakenD v2.7
// schema, endpoints carrying extra_config for rate limiting and CEL
// validation, and nothing in the auth namespace. The accept cases below are
// derived from this same file, so the only difference between a config that is
// refused and one that is served is the credential statement itself.
const liveShape = "tests/fixtures/policy/unstated.json"

// parse runs a config file through the parser the binary runs, so these tests
// exercise the production path from JSON bytes to ServiceConfig rather than a
// struct assembled by hand.
func parse(t *testing.T, path string) config.ServiceConfig {
	t.Helper()
	cfg, err := koanf.New().Parse(path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cfg
}

// restate rewrites a config with edit applied to its endpoint list and returns
// the new path.
func restate(t *testing.T, path string, edit func(endpoints []any)) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	endpoints, _ := doc["endpoints"].([]any)
	edit(endpoints)
	out := filepath.Join(t.TempDir(), "gateway.json")
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(out, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return out
}

// declare sets authPublic on every endpoint.
func declare(open bool) func([]any) {
	return func(endpoints []any) {
		for _, e := range endpoints {
			ep := e.(map[string]any)
			extra, _ := ep["extra_config"].(map[string]any)
			if extra == nil {
				extra = map[string]any{}
				ep["extra_config"] = extra
			}
			extra[authPublic] = open
		}
	}
}

// A config with routes and no credential statement anywhere is refused, and
// the refusal names the count and the key that would fix it.
func TestPolicyRefusesUnstated(t *testing.T) {
	p := readPolicy(parse(t, liveShape))
	if p.routes == 0 {
		t.Fatal("fixture has no endpoints; it cannot exercise the check")
	}
	if p.open != 0 || p.gated != 0 {
		t.Fatalf("fixture states a policy (open=%d gated=%d); it is the wrong fixture", p.open, p.gated)
	}
	err := p.check()
	if err == nil {
		t.Fatalf("check() = nil for %d routes with no credential statement", p.routes)
	}
	for _, want := range []string{fmt.Sprint(p.routes), authPublic} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	t.Logf("routes=%d open=%d gated=%d -> %v", p.routes, p.open, p.gated, err)
}

// One endpoint declaring itself open is NOT a config that states a policy. The
// other 62 still say nothing, and every one of them would demand an identity
// while the process reports healthy.
func TestPolicyRefusesAPartialStatement(t *testing.T) {
	path := restate(t, liveShape, func(endpoints []any) {
		ep := endpoints[0].(map[string]any)
		ep["extra_config"] = map[string]any{authPublic: true}
	})
	p := readPolicy(parse(t, path))
	if p.open != 1 {
		t.Fatalf("open = %d, want 1", p.open)
	}
	err := p.check()
	if err == nil {
		t.Fatal("check() = nil for a config that classified 1 of 63 routes")
	}
	if !strings.Contains(err.Error(), "62") {
		t.Errorf("refusal %q does not name the 62 routes still unsaid", err)
	}
}

// Every route classified, either way, is a config that states a policy.
func TestPolicyAdmitsAFullStatement(t *testing.T) {
	path := restate(t, liveShape, func(endpoints []any) {
		for i, e := range endpoints {
			ep := e.(map[string]any)
			extra, _ := ep["extra_config"].(map[string]any)
			if extra == nil {
				extra = map[string]any{}
				ep["extra_config"] = extra
			}
			extra[authPublic] = i%2 == 0
		}
	})
	p := readPolicy(parse(t, path))
	if p.open+p.gated != p.routes {
		t.Fatalf("routes=%d open=%d gated=%d", p.routes, p.open, p.gated)
	}
	if err := p.check(); err != nil {
		t.Errorf("check() = %v, want nil", err)
	}
}

// An estate with no public surface states that too, and is served.
func TestPolicyAdmitsAllGated(t *testing.T) {
	p := readPolicy(parse(t, restate(t, liveShape, declare(false))))
	if p.gated != p.routes || p.open != 0 {
		t.Fatalf("routes=%d open=%d gated=%d, want all gated", p.routes, p.open, p.gated)
	}
	if err := p.check(); err != nil {
		t.Errorf("check() = %v, want nil", err)
	}
}

// An estate that is entirely public states that too.
func TestPolicyAdmitsAllOpen(t *testing.T) {
	p := readPolicy(parse(t, restate(t, liveShape, declare(true))))
	if p.open != p.routes {
		t.Fatalf("routes=%d open=%d, want all open", p.routes, p.open)
	}
	if err := p.check(); err != nil {
		t.Errorf("check() = %v, want nil", err)
	}
}

// No endpoints is no surface to state a policy about — the smallest config the
// parser accepts, and it boots.
func TestPolicyAdmitsNoRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	body := `{"version":3,"name":"edge","port":8080,"timeout":"30s","endpoints":[]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readPolicy(parse(t, path)).check(); err != nil {
		t.Errorf("check() = %v, want nil", err)
	}
}

// The configs built into this image classify EVERY route, so the binary serves
// the config it ships with — and no route in either of them is unsaid.
func TestPolicyAdmitsShippedConfigs(t *testing.T) {
	for _, path := range []string{"configs/hanzo/gateway.json", "configs/lux/gateway.json"} {
		p := readPolicy(parse(t, path))
		if err := p.check(); err != nil {
			t.Errorf("%s: check() = %v, want nil", path, err)
		}
		if p.open+p.gated != p.routes {
			t.Errorf("%s: %d of %d routes state no policy", path, p.routes-p.open-p.gated, p.routes)
		}
		t.Logf("%s: routes=%d open=%d gated=%d", path, p.routes, p.open, p.gated)
	}
}

// The shipped hanzo config must still mean what canon meant, one route at a
// time: the routes canon gated with auth/validator are the routes this config
// states as needing an identity, and the routes canon left open are the ones it
// states as public. The migration moved where that is written down, not which
// routes are which.
//
// Both sides go through the same parser, because the parser rewrites paths —
// {action} becomes :action — and comparing a parsed path to a raw one compares
// spellings rather than routes.
func TestShippedConfigMatchesTheGatingItReplaced(t *testing.T) {
	raw, err := exec.Command("git", "show", "canon/main:configs/hanzo/gateway.json").Output()
	if err != nil {
		t.Skipf("canon/main not fetched in this checkout: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	canon := map[string]bool{} // route -> gated on canon
	for _, e := range parse(t, path).Endpoints {
		_, gated := e.ExtraConfig["auth/validator"]
		canon[route(e)] = gated
	}

	now := parse(t, "configs/hanzo/gateway.json")
	if len(now.Endpoints) != len(canon) {
		t.Fatalf("%d endpoints now, %d on canon", len(now.Endpoints), len(canon))
	}
	for _, e := range now.Endpoints {
		wasGated, known := canon[route(e)]
		if !known {
			t.Errorf("%s is not on canon", route(e))
			continue
		}
		open, stated := e.ExtraConfig[authPublic].(bool)
		if !stated {
			t.Errorf("%s states no policy", route(e))
			continue
		}
		if open == wasGated {
			t.Errorf("%s: canon gated=%v, this config states open=%v", route(e), wasGated, open)
		}
	}
}

func route(e *config.EndpointConfig) string { return e.Method + " " + e.Endpoint }
