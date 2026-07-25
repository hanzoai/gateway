//go:build legacy
// +build legacy

// Package gateway — config loader tests.
//
// Validates that the koanf-based config parser used by `gateway run -c`
// accepts the operator-emitted JSON shape (port as int) and surfaces a
// usable error when a config-file env override is not parseable as the
// underlying field type.
//
// Background: the runtime parser is `the koanf parser`, which loads the JSON
// file then merges every `KRAKEND_<KEY>` env var into the same key space
// (callback strips the prefix and lowercases). That prefix is a hardcoded
// const upstream — the fork's own service knobs use GATEWAY_ (read via
// os.Getenv in cmd/gateway), but config-file key overrides flow through
// koanf's KRAKEND_ provider. When the env value fails to convert, the
// error message points at the JSON file path, not at the env var, making
// misconfigurations look like a bug in the operator-managed ConfigMap.
// These tests pin the contract end-to-end so any future regression on the
// JSON-int -> Go-int path is caught at build time.

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	koanf "github.com/hanzoai/gateway/v2/internal/plugin/koanf"
)

// loadConfigPath is shared test setup — writes the given JSON body to a
// temp file under the test dir and returns the path.
func loadConfigPath(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

// minimalConfig is the smallest valid v3 config the parser will accept.
// Mirrors the operator-generated ConfigMap shape (port as JSON int).
const minimalConfig = `{
  "version": 3,
  "name": "test",
  "port": 8080,
  "timeout": "30s",
  "endpoints": []
}`

// TestPortAsJSONInt — the canonical, no-env case the operator emits.
// Asserts that `"port": 8080` (int literal) round-trips to ServiceConfig
// without the parser tripping the StringToInt hook (which only fires
// when the value arrives as a string from the env provider).
func TestPortAsJSONInt(t *testing.T) {
	path := loadConfigPath(t, minimalConfig)

	cfg, err := koanf.New().Parse(path)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", path, err)
	}
	if cfg.Port != 8080 {
		t.Fatalf("Port = %d, want 8080", cfg.Port)
	}
}

// TestPortFromEnvNumeric — operator deployments may also set
// KRAKEND_PORT=9090 (always a string at the OS layer). The koanf env
// provider strips the KRAKEND_ prefix, lowercases, and merges, so
// `port` ends up as the string "9090". WeaklyTypedInput + StringToInt
// hook must convert this cleanly. Regression guard for future koanf or
// mapstructure upgrades.
func TestPortFromEnvNumeric(t *testing.T) {
	path := loadConfigPath(t, minimalConfig)

	t.Setenv("KRAKEND_PORT", "9090")

	cfg, err := koanf.New().Parse(path)
	if err != nil {
		t.Fatalf("Parse(%q) with KRAKEND_PORT=9090 failed: %v", path, err)
	}
	if cfg.Port != 9090 {
		t.Fatalf("Port = %d, want 9090 (env override)", cfg.Port)
	}
}

// TestPortFromEnvNonNumeric — documents the failure mode operators can
// trip when KRAKEND_PORT is set to a non-numeric string. The error
// message currently mentions the file path (because koanf attaches it
// during Parse) but the underlying mapstructure field is `'port'`. We
// pin both fragments so anyone reading a future error log can track it
// back to the env override, not to a corrupted ConfigMap.
func TestPortFromEnvNonNumeric(t *testing.T) {
	path := loadConfigPath(t, minimalConfig)

	t.Setenv("KRAKEND_PORT", "not-a-number")

	_, err := koanf.New().Parse(path)
	if err == nil {
		t.Fatalf("Parse(%q) with KRAKEND_PORT=not-a-number unexpectedly succeeded", path)
	}
	msg := err.Error()
	for _, want := range []string{"'port'", "invalid syntax"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message %q missing fragment %q", msg, want)
		}
	}
}

// TestOperatorGeneratedConfig — exact shape of the ConfigMap the Rust
// operator renders for Gateway resources on devnet/testnet/mainnet.
// Port is an int literal, no GATEWAY_ env vars are projected onto the
// pod. Failure here means a v1.0.x bump broke the contract with the
// operator-generated config.
func TestOperatorGeneratedConfig(t *testing.T) {
	body := `{
  "$schema": "https://gateway.hanzo.ai/schema/v2.7/gateway.json",
  "cache_ttl": "0s",
  "endpoints": [],
  "extra_config": {
    "security/cors": {
      "allow_headers": ["Content-Type", "Authorization", "X-Org-Id", "X-Request-ID"],
      "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      "allow_origins": ["https://exchange.test.example.com"],
      "expose_headers": ["Content-Length"],
      "max_age": "12h"
    }
  },
  "name": "Gateway - default",
  "port": 8080,
  "timeout": "30s",
  "version": 3
}`
	path := loadConfigPath(t, body)

	cfg, err := koanf.New().Parse(path)
	if err != nil {
		t.Fatalf("Parse operator-generated config: %v", err)
	}
	if cfg.Port != 8080 {
		t.Fatalf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Version != 3 {
		t.Fatalf("Version = %d, want 3", cfg.Version)
	}
}
