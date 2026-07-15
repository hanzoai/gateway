// Copyright © 2026 Hanzo AI. MIT License.

package gateway

import "testing"

// TestBrandForHost is the white-label isolation contract for the Server header:
// a Host at/under a brand domain (including AltDomains) resolves to that brand,
// the longest domain wins, port and case are normalized, and an unknown Host
// resolves to "" (caller falls back to NeutralServerBrand). A lux/zoo Host must
// never resolve to hanzo.
func TestBrandForHost(t *testing.T) {
	cases := map[string]string{
		"api.hanzo.ai":      "hanzo",
		"hanzo.ai":          "hanzo",
		"hanzo.cloud":       "hanzo",
		"studio.hanzo.app":  "hanzo",
		"api.lux.network":   "lux",
		"api.lux.network.":  "lux", // trailing FQDN dot still resolves (not neutral)
		"lux.network":       "lux",
		"console.lux.cloud": "lux",
		"api.zoo.ngo":       "zoo",
		"zoo.network":       "zoo",
		"console.zoo.cloud": "zoo",
		"api.pars.network":  "pars",
		"pars.ai":           "pars",
		"bootno.de":         "bootnode",
		"API.HANZO.AI:443":  "hanzo", // case + port normalized
		"api.unknown.dev":   "",      // no match -> neutral fallback
		"localhost":         "",
		"10.0.0.5":          "",
	}
	for host, want := range cases {
		if got := brandForHost(host); got != want {
			t.Errorf("brandForHost(%q) = %q, want %q", host, got, want)
		}
	}
	// lux/zoo Hosts never leak hanzo.
	for _, host := range []string{"api.lux.network", "console.lux.cloud", "api.zoo.ngo", "console.zoo.cloud"} {
		if brandForHost(host) == "hanzo" {
			t.Errorf("brandForHost(%q) leaked hanzo on a non-hanzo brand", host)
		}
	}
	// The neutral default is never a framework name.
	for _, bad := range []string{"fasthttp", "fiber", "zip", "krakend", "KrakenD"} {
		if NeutralServerBrand == bad {
			t.Fatalf("NeutralServerBrand is a framework name: %q", NeutralServerBrand)
		}
	}
}
