package gateway

import "net"

// The ZAP listen topology, decided ONCE, here.
//
// UNTAGGED on purpose, unlike the two listeners it governs. zaphttp_listener.go
// is `legacy` and executor.go — the only thing that starts either listener — is
// `legacy` too, but zap_listener.go, which holds the terminator and its
// self-dial guard, is in BOTH builds. A constant that only exists in one build
// cannot constrain a file that exists in both, and these are facts about how the
// fleet is wired, not about which entrypoint was compiled.
//
// Two listeners live in this process and they are not peers:
//
//	zap_listener.go     TLS 1.3+PQ terminator. The ONLY thing on a public
//	                    interface. Terminates, then forwards inward.
//	zaphttp_listener.go the plaintext ZAP server that actually serves the
//	                    composed gateway handler. LOOPBACK, always.
//
// They had a port each, defaulted independently, and both landed on 9999 —
// which is also the port the PUBLIC zap-ingress LoadBalancer targets
// (zap.hanzo.ai). Three spellings of one number across two files and a
// manifest, so nothing could hold the relationship between them, and the
// relationship is the whole safety property. Hence one file, two constants, and
// the one predicate that separates "public" from "loopback".
//
// Why loopback is not merely tidy: ZAP has NO session crypto, in any language.
// There is not a single crypto/tls import anywhere in the zap-proto tree, and
// zap-proto/http listens and dials with bare net.Listen / net.DialTimeout. So
// "plaintext ZAP on a routable interface" is literally cleartext on the wire —
// bearer tokens, prompts, completions — regardless of what a manifest comment
// claims about "TLS 1.3+PQ". The terminator in zap_listener.go is the only
// crypto on this path, and it is inbound-only: there is no outbound TLS ZAP
// dialer in the fleet at all.
const (
	// zapPublicPort is THE public ZAP port: what k8s/hanzo/service.yaml's
	// zap-ingress LoadBalancer forwards, and therefore what the TLS terminator
	// binds. Nothing else may bind it.
	zapPublicPort = 9999

	// zapInternalAddr is where the plaintext ZAP server binds. Loopback, and a
	// DIFFERENT port from zapPublicPort — the terminator forwards here after
	// decrypting. Same-port is not a tuning mistake, it is a self-dial loop:
	// see StartZapListener's guard.
	zapInternalAddr = "127.0.0.1:9998"
)

// isLoopbackHost reports whether a bind host reaches only this host.
//
// The empty host is the case that matters and the one that reads as harmless:
// ":9998" is not "localhost:9998", it is EVERY interface, which is exactly how
// the plaintext server ended up on a public LoadBalancer. A wildcard is not
// loopback.
func isLoopbackHost(host string) bool {
	switch host {
	case "":
		return false // ":9998" — every interface, not loopback
	case "localhost":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
