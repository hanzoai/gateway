package gateway

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/zap-proto/zip"
)

func TestIsWidgetKey(t *testing.T) {
	tests := []struct {
		token    string
		expected bool
	}{
		{"hz_widget_public", true},
		{"hz_custom_key", true},
		{"hk-some-key", false},
		{"sk-openai-key", false},
		{"Bearer hz_widget_public", false}, // raw token, not header
		{"", false},
	}
	for _, tt := range tests {
		if got := isWidgetKey(tt.token); got != tt.expected {
			t.Errorf("isWidgetKey(%q) = %v, want %v", tt.token, got, tt.expected)
		}
	}
}

func TestExtractOriginHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://docs.hanzo.ai", "docs.hanzo.ai"},
		{"http://localhost:3000", "localhost"},
		{"https://hanzo.ai/some/path", "hanzo.ai"},
		{"docs.hanzo.ai", "docs.hanzo.ai"},
		{"", ""},
		{"https://evil.com:8080/path", "evil.com"},
	}
	for _, tt := range tests {
		if got := extractOriginHost(tt.input); got != tt.expected {
			t.Errorf("extractOriginHost(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	allowed := widgetAllowedOrigins([]string{"hanzo.ai", "localhost", "hanzo.bot"})
	tests := []struct {
		host     string
		expected bool
	}{
		{"hanzo.ai", true},
		{"docs.hanzo.ai", true},      // subdomain match
		{"www.hanzo.ai", true},       // subdomain match
		{"app.hanzo.bot", true},      // subdomain match
		{"localhost", true},          // exact match
		{"evil.com", false},          // not allowed
		{"nothanzo.ai", false},       // partial suffix, not subdomain
		{"evil.com.hanzo.ai", true},  // subdomain (technically valid)
		{"hanzo.ai.evil.com", false}, // suffix attack
		{"", false},                  // empty
	}
	for _, tt := range tests {
		if got := isAllowedOrigin(tt.host, allowed); got != tt.expected {
			t.Errorf("isAllowedOrigin(%q) = %v, want %v", tt.host, got, tt.expected)
		}
	}
}

func TestWidgetRateLimiterPerIP(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  3,
		Window:            1 * time.Second,
		GlobalMaxRequests: 100,
		CleanupInterval:   1 * time.Hour, // don't cleanup during test
	}
	rl := newWidgetRateLimiter(cfg)

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		if !rl.allow("192.168.1.1") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied
	if rl.allow("192.168.1.1") {
		t.Error("request 4 should be denied (per-IP limit)")
	}

	// Different IP should still be allowed
	if !rl.allow("192.168.1.2") {
		t.Error("different IP should be allowed")
	}
}

func TestWidgetRateLimiterGlobal(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  100, // high per-IP limit
		Window:            1 * time.Second,
		GlobalMaxRequests: 3, // low global limit
		CleanupInterval:   1 * time.Hour,
	}
	rl := newWidgetRateLimiter(cfg)

	// Use different IPs to hit global limit
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !rl.allow(ip) {
			t.Errorf("request %d from %s should be allowed", i+1, ip)
		}
	}

	// 4th request from new IP should be denied (global limit)
	if rl.allow("10.0.0.99") {
		t.Error("request should be denied (global limit)")
	}
}

func TestWidgetRateLimiterWindowExpiry(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  2,
		Window:            50 * time.Millisecond,
		GlobalMaxRequests: 100,
		CleanupInterval:   1 * time.Hour,
	}
	rl := newWidgetRateLimiter(cfg)

	// Use up the limit
	rl.allow("1.2.3.4")
	rl.allow("1.2.3.4")
	if rl.allow("1.2.3.4") {
		t.Error("should be denied before window expires")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if !rl.allow("1.2.3.4") {
		t.Error("should be allowed after window expires")
	}
}

// --- The gate on the wire ---
//
// These drive the NATIVE zip transport (zipWidget), which is the edge the
// unified cloud binary runs and, until the policy became a value, the edge that
// enforced none of this. The gin transport is driven over the same cases in
// transport_parity_test.go, which additionally asserts the two agree.

// widgetRequest runs one request through zipWidget and reports the status.
func widgetRequest(t *testing.T, h zip.Handler, hdr map[string]string) int {
	t.Helper()
	return zipEdge(t, h, http.MethodPost, "/v1/chat/completions", "api.hanzo.ai", hdr).status
}

// A widget key is a PUBLIC credential embedded in client-side JS. Without an
// Origin (or Referer) it is a credential in a script, not in a browser, and the
// gate refuses it — the caller is told which credential to use instead.
func TestWidgetGate_OriginRequired(t *testing.T) {
	gate := zipWidget(DefaultWidgetSecurityConfig())
	if code := widgetRequest(t, gate, map[string]string{
		"Authorization": "Bearer hz_widget_public",
	}); code != http.StatusForbidden {
		t.Errorf("widget key without Origin should get 403, got %d", code)
	}
}

// A brand subdomain is allowed with no per-origin configuration — the suffix
// match in isAllowedOrigin is what lets a new Hanzo property embed the widget
// without a deploy.
func TestWidgetGate_OriginAllowed(t *testing.T) {
	gate := zipWidget(DefaultWidgetSecurityConfig())
	if code := widgetRequest(t, gate, map[string]string{
		"Authorization": "Bearer hz_widget_public",
		"Origin":        "https://docs.hanzo.ai",
	}); code != http.StatusOK {
		t.Errorf("widget key with valid Origin should pass, got %d", code)
	}
}

func TestWidgetGate_OriginRejected(t *testing.T) {
	gate := zipWidget(DefaultWidgetSecurityConfig())
	if code := widgetRequest(t, gate, map[string]string{
		"Authorization": "Bearer hz_widget_public",
		"Origin":        "https://evil.com",
	}); code != http.StatusForbidden {
		t.Errorf("widget key from evil.com should get 403, got %d", code)
	}
}

// The per-IP window, on the wire: the cap is what stops one page draining the
// model budget with a key anyone can read out of its source.
func TestWidgetGate_RateLimit(t *testing.T) {
	cfg := DefaultWidgetSecurityConfig()
	cfg.MaxRequestsPerIP = 2
	cfg.Window = 1 * time.Second
	gate := zipWidget(cfg)

	hdr := map[string]string{
		"Authorization": "Bearer hz_widget_public",
		"Origin":        "https://docs.hanzo.ai",
	}
	for i := 0; i < 2; i++ {
		if code := widgetRequest(t, gate, hdr); code != http.StatusOK {
			t.Errorf("request %d should succeed, got %d", i+1, code)
		}
	}
	if code := widgetRequest(t, gate, hdr); code != http.StatusTooManyRequests {
		t.Errorf("request 3 should get 429, got %d", code)
	}
}

// Everything that is not a widget key passes through untouched — the gate acts
// on hz_ bearers and on nothing else.
func TestWidgetGate_NonWidgetPassthrough(t *testing.T) {
	gate := zipWidget(DefaultWidgetSecurityConfig())
	if code := widgetRequest(t, gate, map[string]string{
		"Authorization": "Bearer hk-some-api-key",
	}); code != http.StatusOK {
		t.Errorf("non-widget key should pass through, got %d", code)
	}
}

// Referer stands in for Origin: a top-level navigation sends one and not the
// other, and a widget on a real page must still work.
func TestWidgetGate_RefererFallback(t *testing.T) {
	gate := zipWidget(DefaultWidgetSecurityConfig())
	if code := widgetRequest(t, gate, map[string]string{
		"Authorization": "Bearer hz_widget_public",
		"Referer":       "https://hanzo.ai/pricing",
	}); code != http.StatusOK {
		t.Errorf("widget key with valid Referer should pass, got %d", code)
	}
}
