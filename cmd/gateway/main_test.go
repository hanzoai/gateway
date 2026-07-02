// Copyright © 2026 Hanzo AI. Apache-2.0 License.

//go:build !legacy
// +build !legacy

package main

import (
	"os"
	"testing"
	"time"
)

// TestShutdownGraceFromEnv verifies the GATEWAY_SHUTDOWN_TIMEOUT parsing
// helper. The full SIGTERM-triggered drain path is exercised by deployment
// smoke tests (not safe to interrupt the in-process Go test runner with
// SIGTERM), so this isolated unit test guarantees the helper's contract:
// env-driven override + safe fallback on malformed/zero/negative values.
func TestShutdownGraceFromEnv(t *testing.T) {
	def := 30 * time.Second
	cases := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset", "", def},
		{"valid_seconds", "45s", 45 * time.Second},
		{"valid_minutes", "2m", 2 * time.Minute},
		{"malformed", "not-a-duration", def},
		{"zero_rejected", "0s", def},
		{"negative_rejected", "-5s", def},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev, hadPrev := os.LookupEnv("GATEWAY_SHUTDOWN_TIMEOUT")
			t.Cleanup(func() {
				if hadPrev {
					os.Setenv("GATEWAY_SHUTDOWN_TIMEOUT", prev)
				} else {
					os.Unsetenv("GATEWAY_SHUTDOWN_TIMEOUT")
				}
			})
			if tc.env == "" {
				os.Unsetenv("GATEWAY_SHUTDOWN_TIMEOUT")
			} else {
				os.Setenv("GATEWAY_SHUTDOWN_TIMEOUT", tc.env)
			}
			got := shutdownGraceFromEnv(def)
			if got != tc.want {
				t.Fatalf("env=%q: want %v got %v", tc.env, tc.want, got)
			}
		})
	}
}

// TestEnvOr smoke-tests the envOr helper since the file is otherwise
// shutdown-focused and a green build benefits from a second covered helper.
func TestEnvOr(t *testing.T) {
	const key = "GATEWAY_TEST_ENV_OR_UNIQUE"
	os.Unsetenv(key)
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Fatalf("unset: want fallback, got %q", got)
	}
	os.Setenv(key, "set")
	t.Cleanup(func() { os.Unsetenv(key) })
	if got := envOr(key, "fallback"); got != "set" {
		t.Fatalf("set: want set, got %q", got)
	}
}
