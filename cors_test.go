// Copyright © 2026 Hanzo AI. MIT License.

// Untagged on purpose: [corsAllowHeaders] is a framework-free value, so it is
// exercised under BOTH builds. The transport suites around it are tagged because
// each drives one edge.

package gateway

import "testing"

// TestCORSAllowHeaders_AnswersTheAsk is the regression for the defect a literal
// allow-headers list guarantees: a client attaches a header nobody added, the
// preflight does not name it, and the browser kills the request with an opaque
// "TypeError: Failed to fetch" that never reaches a log.
//
// This copy had drifted four names behind cloud's, which is what a second literal
// list of the same thing always does. The names below are the ones it was missing
// — the console's four, and the X-Idempotency-Key the billing checkout stamps on
// POST /v1/billing/subscribe/card. Any header must work; that is the point.
func TestCORSAllowHeaders_AnswersTheAsk(t *testing.T) {
	for _, ask := range []string{
		"content-type, x-idempotency-key",
		"x-actor-id, x-act-as-project, x-act-as-org, x-csrf-token",
		"x-something-nobody-has-added-yet",
	} {
		if got := corsAllowHeaders(ask); got != ask {
			t.Errorf("corsAllowHeaders(%q) = %q — the browser could not send what it asked about", ask, got)
		}
	}
}

// TestCORSAllowHeaders_EchoesTokensOnly: the echo is a header VALUE, so a
// hand-written ask must not be able to fold anything into the response.
func TestCORSAllowHeaders_EchoesTokensOnly(t *testing.T) {
	cases := []struct{ ask, want string }{
		{"", ""},
		{"Content-Type", "Content-Type"},
		{" x-a , x-b ", "x-a, x-b"},
		{"x-a,,x-b", "x-a, x-b"},                 // an empty name is not a name
		{"x-ok\r\nX-Injected: 1", ""},            // CRLF makes the WHOLE name malformed
		{"x-ok, x-bad\r\nX-Injected: 1", "x-ok"}, // …and only the malformed one is dropped
		{"x-ok, bad header", "x-ok"},             // a space is not a tchar
		{"x-ok, \"quoted\"", "x-ok"},             // nor is a quote
	}
	for _, tc := range cases {
		if got := corsAllowHeaders(tc.ask); got != tc.want {
			t.Errorf("corsAllowHeaders(%q) = %q, want %q", tc.ask, got, tc.want)
		}
	}
}
