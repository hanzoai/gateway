// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import "testing"

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
