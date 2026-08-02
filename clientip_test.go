// Copyright © 2026 Hanzo AI. MIT License.

package gateway

import "testing"

// The whole point of the policy: a client cannot choose its own rate-limit
// bucket. Every case below is a request a client could construct.
func TestPeerPolicy_ClientIP(t *testing.T) {
	p := newPeerPolicy()

	cases := []struct {
		name      string
		peer      string
		forwarded string
		want      string
	}{
		// A peer we do not run is the client, and its own claim about itself is
		// discarded — this is the case gin got wrong, returning 198.51.100.7.
		{"direct client cannot forge", "203.0.113.9", "198.51.100.7", "203.0.113.9"},
		{"direct client cannot forge a chain", "203.0.113.9", "10.0.0.1, 127.0.0.1", "203.0.113.9"},
		{"direct client, no header", "203.0.113.9", "", "203.0.113.9"},

		// Behind our own ingress the chain IS evidence, as far as it is ours.
		{"ingress forwards the client", "10.150.104.186", "203.0.113.9", "203.0.113.9"},
		{"rightmost untrusted hop wins", "10.150.104.186", "203.0.113.9, 198.51.100.4", "198.51.100.4"},
		{"padding left of the real hop is ignored", "10.150.104.186", "1.1.1.1, 2.2.2.2, 203.0.113.9", "203.0.113.9"},
		{"our own hops are skipped", "10.150.104.186", "203.0.113.9, 10.4.5.6, 10.7.8.9", "203.0.113.9"},

		// Nothing to attribute: bucket on something a client cannot steer.
		{"trusted peer, no header", "10.150.104.186", "", "10.150.104.186"},
		{"whole chain is in-cluster", "10.150.104.186", "10.1.2.3, 10.4.5.6", "10.1.2.3"},
		{"malformed hop ends the chain", "10.150.104.186", "203.0.113.9, garbage", "10.150.104.186"},

		// Shapes a transport actually hands us.
		{"peer with port", "203.0.113.9:53314", "", "203.0.113.9"},
		{"v6 peer with port", "[2001:db8::1]:443", "", "2001:db8::1"},
		{"v4-mapped v6 loopback is loopback", "::ffff:127.0.0.1", "203.0.113.9", "203.0.113.9"},
		{"forwarded entry with spaces", "10.150.104.186", "  203.0.113.9  ", "203.0.113.9"},
		{"unparsable peer is its own bucket", "", "203.0.113.9", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.clientIP(tc.peer, tc.forwarded); got != tc.want {
				t.Errorf("clientIP(%q, %q) = %q, want %q", tc.peer, tc.forwarded, got, tc.want)
			}
		})
	}
}

// The measured live defect, as a test: 20 requests from one peer with a rotating
// X-Forwarded-For must be twenty requests from ONE bucket. On the live lux-ns
// edge they were twenty buckets and the 10/min cap never tripped.
func TestPeerPolicy_RotatingForwardedForIsOneBucket(t *testing.T) {
	p := newPeerPolicy()
	const peer = "203.0.113.9" // the attacker's real socket peer

	first := p.clientIP(peer, "198.51.100.1")
	for i := 2; i <= 20; i++ {
		got := p.clientIP(peer, "198.51.100."+itoa(i))
		if got != first {
			t.Fatalf("rotating X-Forwarded-For moved the bucket: %q then %q", first, got)
		}
	}
	if first != peer {
		t.Errorf("bucketed on %q, want the real peer %q", first, peer)
	}
}

// An operator fronting the edge with a CDN widens the trusted set; nothing else
// about the walk changes.
func TestPeerPolicy_TrustedSetIsConfigurable(t *testing.T) {
	t.Setenv("GATEWAY_TRUSTED_PROXIES", "198.51.100.0/24")
	p := newPeerPolicy()

	if got := p.clientIP("198.51.100.4", "203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("configured proxy should be trusted to forward: got %q", got)
	}
	// The defaults are REPLACED, not merged: a private peer is no longer trusted.
	if got := p.clientIP("10.150.104.186", "203.0.113.9"); got != "10.150.104.186" {
		t.Errorf("default range should no longer be trusted: got %q", got)
	}
}

// A typo must make the gate trust LESS, never more.
func TestPeerPolicy_UnparsableCIDRNarrows(t *testing.T) {
	t.Setenv("GATEWAY_TRUSTED_PROXIES", "not-a-cidr, 10.0.0.0/8")
	p := newPeerPolicy()

	if got := p.clientIP("10.150.104.186", "203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("the valid half should still be trusted: got %q", got)
	}
	if got := p.clientIP("127.0.0.1", "203.0.113.9"); got != "127.0.0.1" {
		t.Errorf("a dropped entry must not widen trust: got %q", got)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
