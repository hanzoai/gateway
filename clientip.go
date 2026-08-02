// Copyright © 2026 Hanzo AI. MIT License.

// clientip.go answers "which client is this" — ONCE, for both edges.
//
// A rate limit is only as good as the key it buckets on, and until now each
// transport supplied that key from its own framework:
//
//	gin's ClientIP()  trusts X-Forwarded-For from EVERY peer — gin's
//	                  defaultTrustedCIDRs is 0.0.0.0/0 + ::/0 and this repo never
//	                  calls SetTrustedProxies — and then returns the LEFTMOST
//	                  entry, which is the one the client wrote.
//
//	fiber's IP()      ignores X-Forwarded-For entirely (zip sets no ProxyHeader,
//	                  so it returns fasthttp's RemoteIP), so behind hanzoai/ingress
//	                  every request in the cluster carries the SAME peer — the
//	                  ingress pod.
//
// One is forgeable and the other is a self-DoS: a 10/min per-IP cap that either
// never trips or trips once for the whole internet. Both were measured on the
// live lux-ns edge — 20 requests with a rotating X-Forwarded-For never hit the
// cap, and the gin access log printed the forged address as the client.
//
// transport_parity_test.go could not see either, because its two harnesses never
// set a forwarded header and never vary the peer: both edges answered about the
// same nothing, and agreed. So the peer becomes a value, like every other
// decision in this package — a trusted set and a walk over it, stated here and
// asked by both transports.
package gateway

import (
	"net/netip"
	"os"
	"strings"
)

// defaultTrustedProxies is the set a gateway pod's peers actually occupy: the
// loopback it is probed on, and the private ranges an in-cluster ingress lives
// in. A peer OUTSIDE this set reached the gateway directly, and a direct client's
// own X-Forwarded-For is worth exactly nothing.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128", // loopback — probes, and the pod's own callers
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918 — pod and service CIDRs
	"100.64.0.0/10",  // CGNAT — DOKS node pools
	"169.254.0.0/16", // link-local
	"fe80::/10",      // link-local v6
	"fc00::/7",       // unique-local v6
}

// peerPolicy is the compiled trusted-proxy set. Build it with [newPeerPolicy]
// and ask it per request.
type peerPolicy struct{ trusted []netip.Prefix }

// newPeerPolicy compiles the trusted set once, from the environment.
//
// GATEWAY_TRUSTED_PROXIES REPLACES the default with a comma-separated CIDR list.
// An operator fronting this edge with a CDN adds the CDN's ranges there; until
// they do, the CDN's own address is what gets bucketed — coarser than the true
// client, never forgeable by one.
//
// An unparsable entry is DROPPED rather than defaulted. That narrows the trusted
// set, so a typo makes the gate trust less and limit harder — the direction a
// config error should fail in.
func newPeerPolicy() peerPolicy {
	spec := defaultTrustedProxies
	if env := os.Getenv("GATEWAY_TRUSTED_PROXIES"); env != "" {
		spec = strings.Split(env, ",")
	}
	var p peerPolicy
	for _, c := range spec {
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			p.trusted = append(p.trusted, pfx.Masked())
		}
	}
	return p
}

func (p peerPolicy) isTrusted(a netip.Addr) bool {
	for _, pfx := range p.trusted {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the address a rate limit should bucket on.
//
// peer is the transport's own view of the SOCKET peer — gin's RemoteIP(), zip's
// Fiber().IP() — never its ClientIP()-style helper, which is the forgeable thing
// this replaces. forwarded is the raw X-Forwarded-For.
//
// The walk is right-to-left, returning the first hop that is not itself a trusted
// proxy. X-Forwarded-For is APPENDED by each hop, so everything to the right of
// the last trusted proxy was written by infrastructure we run, and everything
// left of the first untrusted entry was written by someone we do not. A client
// that pads the header only pads the part already discarded.
func (p peerPolicy) clientIP(peer, forwarded string) string {
	addr, ok := parseAddr(peer)
	if !ok {
		// An unparsable peer is one bucket for all of it. That limits harder
		// than guessing, and it cannot be steered by a client.
		return peer
	}
	if !p.isTrusted(addr) {
		// Direct client: its own header is not evidence about itself.
		return addr.String()
	}
	var leftmost string
	hops := strings.Split(forwarded, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseAddr(hops[i])
		if !ok {
			// A malformed hop ends the chain: nothing further left can be
			// attributed, so stop rather than skip past it.
			break
		}
		if !p.isTrusted(hop) {
			return hop.String()
		}
		leftmost = hop.String()
	}
	if leftmost != "" {
		// Every hop is ours, so the caller is in-cluster and the leftmost entry
		// is the one that started it.
		return leftmost
	}
	return addr.String()
}

// parseAddr accepts what a transport or a forwarded header actually carries: a
// bare address, a host:port (bracketed or not), and surrounding space. The
// result is Unmap'd so an IPv4-mapped IPv6 peer — which is what fasthttp reports
// on a dual-stack listener — matches the IPv4 prefixes above.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
