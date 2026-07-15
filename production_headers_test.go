// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/core"
)

// TestProductionHeadersMiddleware is the deployed (legacy gin) edge contract:
// the response carries the white-label brand of the request Host in Server, the
// brand-neutral X-Api-Version, and the HSTS + nosniff floor; every
// framework-leaking header (X-KRAKEND, X-Powered-By) is stripped; and a lux/zoo
// caller never sees "hanzo" or the framework name.
func TestProductionHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Deterministically exercise the X-Api-Version path.
	saved := core.KrakendVersion
	core.KrakendVersion = "2.13.0"
	defer func() { core.KrakendVersion = saved }()

	r := gin.New()
	r.Use(ProductionHeadersMiddleware())
	r.GET("/x", func(c *gin.Context) {
		// Simulate the upstream SDK leaking framework headers before the write.
		c.Header("X-KRAKEND", "Version 2.13")
		c.Header("X-Powered-By", "hanzoai/gateway Version 2.13.0")
		c.String(http.StatusOK, "ok")
	})

	cases := map[string]string{
		"api.hanzo.ai":      "hanzo",
		"api.lux.network":   "lux",
		"console.lux.cloud": "lux",
		"api.zoo.ngo":       "zoo",
		"console.zoo.cloud": "zoo",
		"api.pars.network":  "pars",
		"probe.internal":    NeutralServerBrand, // unmatched -> neutral
	}
	for host, wantServer := range cases {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
		req.Host = host
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Server"); got != wantServer {
			t.Errorf("Host %q: Server=%q want %q", host, got, wantServer)
		}
		if got := w.Header().Get("X-KRAKEND"); got != "" {
			t.Errorf("Host %q: X-KRAKEND leaked: %q", host, got)
		}
		if got := w.Header().Get("X-Powered-By"); got != "" {
			t.Errorf("Host %q: X-Powered-By leaked: %q", host, got)
		}
		if got := w.Header().Get("X-Api-Version"); got != "2.13.0" {
			t.Errorf("Host %q: X-Api-Version=%q want 2.13.0", host, got)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("Host %q: X-Content-Type-Options=%q want nosniff", host, got)
		}
		if got := w.Header().Get("Strict-Transport-Security"); got == "" {
			t.Errorf("Host %q: missing Strict-Transport-Security", host)
		}
		for _, bad := range []string{"fasthttp", "fiber", "zip", "KrakenD", "krakend", "hanzoai"} {
			if w.Header().Get("Server") == bad {
				t.Errorf("Host %q: Server leaked framework/brand %q", host, bad)
			}
		}
	}

	// lux/zoo Hosts never resolve to hanzo, even under the deployed edge.
	for _, host := range []string{"api.lux.network", "console.zoo.cloud"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
		req.Host = host
		r.ServeHTTP(w, req)
		if w.Header().Get("Server") == "hanzo" {
			t.Errorf("Host %q leaked hanzo on the deployed edge", host)
		}
	}
}
