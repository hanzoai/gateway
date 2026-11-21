package token

import (
	"slices"
	"testing"
)

// While the platform's issuer moves from hanzo.id to hanzo.ai the allowlist holds both
// (AUTH_ISSUER and WHITELABEL_ISSUERS), each compared verbatim, and never an organization's
// own issuer, which sits one path segment under hanzo.ai.
func TestIssuersHoldBothPlatformIssuersAndNotAnOrgs(t *testing.T) {
	t.Setenv("AUTH_ISSUER", "https://hanzo.id")
	t.Setenv("WHITELABEL_ISSUERS", "https://hanzo.ai")
	got := IssuersFromEnv()
	for _, want := range []string{"https://hanzo.id", "https://hanzo.ai"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is not trusted: %v", want, got)
		}
	}
	for _, not := range []string{"https://hanzo.ai/acme", "https://hanzo.ai/", "http://hanzo.ai", "https://hanzo.ai.evil.test"} {
		if accepts(got, not) {
			t.Errorf("%s is trusted: %v", not, got)
		}
	}
}
