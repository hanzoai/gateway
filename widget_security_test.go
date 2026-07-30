package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

func TestWidgetSecurityMiddlewareOriginRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	middleware := NewWidgetSecurityMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Widget key without Origin header should be rejected
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hz_widget_public")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("widget key without Origin should get 403, got %d", w.Code)
	}
}

func TestWidgetSecurityMiddlewareOriginAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	middleware := NewWidgetSecurityMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Widget key with valid Origin should pass
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hz_widget_public")
	req.Header.Set("Origin", "https://docs.hanzo.ai")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("widget key with valid Origin should pass, got %d", w.Code)
	}
}

func TestWidgetSecurityMiddlewareOriginRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	middleware := NewWidgetSecurityMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Widget key with unknown Origin should be rejected
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hz_widget_public")
	req.Header.Set("Origin", "https://evil.com")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("widget key from evil.com should get 403, got %d", w.Code)
	}
}

func TestWidgetSecurityMiddlewareRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	cfg.MaxRequestsPerIP = 2
	cfg.Window = 1 * time.Second
	middleware := NewWidgetSecurityMiddleware(cfg)

	r := gin.New()
	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	makeReq := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Authorization", "Bearer hz_widget_public")
		req.Header.Set("Origin", "https://docs.hanzo.ai")
		r.ServeHTTP(w, req)
		return w.Code
	}

	// First 2 should succeed
	for i := 0; i < 2; i++ {
		if code := makeReq(); code != http.StatusOK {
			t.Errorf("request %d should succeed, got %d", i+1, code)
		}
	}

	// 3rd should be rate limited
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("request 3 should get 429, got %d", code)
	}
}

func TestWidgetSecurityMiddlewareNonWidgetPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	middleware := NewWidgetSecurityMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Non-widget key should pass through without Origin check
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hk-some-api-key")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("non-widget key should pass through, got %d", w.Code)
	}
}

func TestWidgetSecurityMiddlewareRefererFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := DefaultWidgetSecurityConfig()
	middleware := NewWidgetSecurityMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Widget key with Referer (no Origin) should use Referer for validation
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hz_widget_public")
	req.Header.Set("Referer", "https://hanzo.ai/pricing")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("widget key with valid Referer should pass, got %d", w.Code)
	}
}
