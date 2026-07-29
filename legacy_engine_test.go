// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// Regression guards for NewEngine's two overrides of lura's router config.
//
// Both were WRITE-ONLY over the operator's `router` extra_config, and both
// reproduced against the SHIPPING config (configs/hanzo/gateway.json) with the
// real binary, not just in the fixture suite:
//
//   - the disable_health injection REPLACED the whole `router` map, so
//     `return_error_msg: true` — set in configs/hanzo, configs/lux AND
//     tests/fixtures — never reached lura. Every upstream failure answered with
//     a bare status and Content-Length: 0.
//   - `engine.RedirectFixedPath = false` ran AFTER lura's NewEngine, so lura's
//     own `disable_redirect_fixed_path` knob was dead and a case-differing path
//     404'd instead of redirecting.
//
// The tests below are the *unit* pins. tests/fixtures/specs/router_redirect.json
// and backend_404/cel-1/cel-2/lua_2 are the end-to-end ones.
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	luragin "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
)

// TestWithRouterOption_PreservesOperatorKeys is the direct pin on the clobber:
// forcing one key must not drop the others.
func TestWithRouterOption_PreservesOperatorKeys(t *testing.T) {
	operator := map[string]interface{}{"return_error_msg": true, "auto_options": true}
	ec := config.ExtraConfig{luragin.Namespace: operator}

	got, ok := withRouterOption(ec, "disable_health", true)[luragin.Namespace].(map[string]interface{})
	if !ok {
		t.Fatalf("router namespace is not a map: %#v", ec[luragin.Namespace])
	}
	for k, want := range map[string]interface{}{
		"return_error_msg": true,
		"auto_options":     true,
		"disable_health":   true,
	} {
		if got[k] != want {
			t.Errorf("router[%q] = %v, want %v (full map: %#v)", k, got[k], want, got)
		}
	}
	// Copy-on-write: the service config is shared with the check/audit commands,
	// so forcing an option must not mutate the caller's nested map.
	if _, mutated := operator["disable_health"]; mutated {
		t.Error("withRouterOption mutated the operator's map in place")
	}
}

// TestNewEngine_KeepsOperatorRouterConfig is the pin on the clobber as NewEngine
// itself performs it. The config it hands lura must still carry the operator's
// keys — `return_error_msg: true` is set in configs/hanzo, configs/lux and
// tests/fixtures, and losing it is what emptied every 5xx body on the edge.
func TestNewEngine_KeepsOperatorRouterConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.ServiceConfig{
		ExtraConfig: config.ExtraConfig{
			luragin.Namespace: map[string]interface{}{"return_error_msg": true},
		},
	}
	e := NewEngine(cfg, luragin.EngineOptions{})

	router, ok := cfg.ExtraConfig[luragin.Namespace].(map[string]interface{})
	if !ok {
		t.Fatalf("router namespace is not a map: %#v", cfg.ExtraConfig[luragin.Namespace])
	}
	if router["return_error_msg"] != true {
		t.Errorf("return_error_msg = %v, want true — NewEngine dropped the operator's router config: %#v",
			router["return_error_msg"], router)
	}
	if router["disable_health"] != true {
		t.Errorf("disable_health = %v, want true — the forced option did not land: %#v",
			router["disable_health"], router)
	}

	// ...and the engine still serves: the merge did not corrupt what lura reads.
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no-such-endpoint", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Server"); got != "gateway" {
		t.Errorf("Server = %q, want %q — ProductionHeadersMiddleware did not run", got, "gateway")
	}
}

// TestNewEngine_MixedStaticParamRoutes_FixedPathRedirect is the load-bearing
// one. `engine.RedirectFixedPath = false` was carried with a comment blaming a
// gin 1.9.1 panic on mixed static/param nodes (gin-gonic/gin#3348). gin is
// v1.12.0 now; this pins that the panic is gone AND that the redirect works, so
// the removal is not a trade of a 404 for a crash.
//
// The route shape is the production one: a static segment with a param sibling
// and a static child under the param (configs/hanzo/gateway.json ships
// /v1/async-invoke, /v1/async-invoke/{id} and /v1/async-invoke/{id}/status).
func TestNewEngine_MixedStaticParamRoutes_FixedPathRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := NewEngine(config.ServiceConfig{}, luragin.EngineOptions{})

	ok := func(c *gin.Context) { c.String(http.StatusOK, "ok") }
	for _, p := range []string{
		"/v1/async-invoke",
		"/v1/async-invoke/:request_id",
		"/v1/async-invoke/:request_id/status",
		"/v1/ats/assets/:id/quote",
		"/v1/ats/assets/search",
	} {
		e.GET(p, ok) // panics here if #3348 were still live
	}

	for _, tc := range []struct {
		path, want string
		code       int
	}{
		{"/v1/async-invoke", "", http.StatusOK},
		{"/V1/Async-Invoke", "/v1/async-invoke", http.StatusMovedPermanently},
		{"/v1/ATS/assets/search", "/v1/ats/assets/search", http.StatusMovedPermanently},
	} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.code {
			t.Errorf("GET %s: status = %d, want %d", tc.path, rec.Code, tc.code)
		}
		if tc.want != "" && rec.Header().Get("Location") != tc.want {
			t.Errorf("GET %s: Location = %q, want %q", tc.path, rec.Header().Get("Location"), tc.want)
		}
	}
}

// TestNewEngine_OperatorCanDisableFixedPathRedirect pins that deleting the
// hardcode restored the KNOB rather than replacing one hardcode with another:
// lura's `disable_redirect_fixed_path` is the one way to turn it off.
func TestNewEngine_OperatorCanDisableFixedPathRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := NewEngine(config.ServiceConfig{
		ExtraConfig: config.ExtraConfig{
			luragin.Namespace: map[string]interface{}{"disable_redirect_fixed_path": true},
		},
	}, luragin.EngineOptions{})
	e.GET("/v1/models", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/V1/Models", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("with disable_redirect_fixed_path: status = %d, want 404", rec.Code)
	}
}
