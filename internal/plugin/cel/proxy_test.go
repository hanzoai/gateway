package cel

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/plugin/cel/internal"
)

// liveInfoRule is the expression the lux edge actually runs, copied verbatim
// out of ConfigMap api-gateway-gateway-config on lux-mainnet, where it guards
// POST /v1/info for api.lux.network, api.hanzo.network, api.zoo.network,
// api.spc.network and api.pars.network.
//
// It does not compile, and cannot be made to: `has()` is a CEL macro over a
// FIELD SELECTION (`has(msg.field)`), so `has(req_body)` on a bare identifier
// is rejected by the parser no matter what the environment declares. The rule
// reads as an allowlist of four info methods and has never once been applied.
const liveInfoRule = `has(req_body) && (req_body.matches('.*"info\\.getNetworkID".*') || ` +
	`req_body.matches('.*"info\\.getNetworkName".*') || ` +
	`req_body.matches('.*"info\\.getBlockchainID".*') || ` +
	`req_body.matches('.*"info\\.isBootstrapped".*'))`

// fixedInfoRule is the same policy, expressed in CEL that compiles.
//
// The `has()` guard is not merely removable, it was never needed: req_body is
// declared as a string and is "" when there is no body, so an empty body
// matches none of the four alternatives and is refused. Fail-closed falls out
// of the allowlist itself.
const fixedInfoRule = `req_body.matches('.*"info\\.getNetworkID".*') || ` +
	`req_body.matches('.*"info\\.getNetworkName".*') || ` +
	`req_body.matches('.*"info\\.getBlockchainID".*') || ` +
	`req_body.matches('.*"info\\.isBootstrapped".*')`

func celConfig(expr string) config.ExtraConfig {
	return config.ExtraConfig{
		internal.Namespace: []interface{}{
			map[string]interface{}{"check_expr": expr},
		},
	}
}

// echoFactory is the "backend": it records the body it was handed so a test
// can prove the payload still arrives intact after being read for evaluation.
func echoFactory(seen *string) proxy.FactoryFunc {
	return proxy.FactoryFunc(func(_ *config.EndpointConfig) (proxy.Proxy, error) {
		return func(_ context.Context, r *proxy.Request) (*proxy.Response, error) {
			if r.Body != nil {
				b, _ := io.ReadAll(r.Body)
				*seen = string(b)
			}
			return &proxy.Response{IsComplete: true}, nil
		}, nil
	})
}

func rpc(method string) *proxy.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`
	return &proxy.Request{
		Method: "POST",
		Path:   "/v1/info",
		Body:   io.NopCloser(strings.NewReader(body)),
	}
}

// TestLiveRule_BlocksPeersAllowsBootstrapped is the regression for the
// exposure. Before req_body was declared, this expression could not compile,
// ProxyFactory swallowed the error and returned the unguarded pipe, and BOTH
// calls below reached the backend.
func TestLiveRule_BlocksPeersAllowsBootstrapped(t *testing.T) {
	var seen string
	p, err := ProxyFactory(logging.NoOp, echoFactory(&seen)).New(&config.EndpointConfig{
		Endpoint:    "/v1/info",
		ExtraConfig: celConfig(fixedInfoRule),
	})
	if err != nil {
		t.Fatalf("the corrected rule must compile: %v", err)
	}

	if _, err := p(context.Background(), rpc("info.isBootstrapped")); err != nil {
		t.Fatalf("info.isBootstrapped is on the allowlist and must pass: %v", err)
	}
	if seen == "" {
		t.Fatal("backend received no body: reading it for evaluation consumed it")
	}
	if !strings.Contains(seen, "info.isBootstrapped") {
		t.Fatalf("backend got a mangled body: %q", seen)
	}

	seen = ""
	if _, err := p(context.Background(), rpc("info.peers")); err == nil {
		t.Fatal("info.peers is NOT on the allowlist and must be refused")
	}
	if seen != "" {
		t.Fatalf("info.peers reached the backend anyway: %q", seen)
	}
}

// TestUncompilableCheck_RefusesToServe covers the failure mode that hid the
// exposure: a declared check that cannot be compiled used to log two Warnings
// and hand back the pipe WITHOUT the check, so the endpoint served everything
// while its config still read as guarded.
func TestUncompilableCheck_RefusesToServe(t *testing.T) {
	var seen string
	p, err := ProxyFactory(logging.NoOp, echoFactory(&seen)).New(&config.EndpointConfig{
		Endpoint:    "/v1/info",
		ExtraConfig: celConfig(`req_nonexistent.matches('x')`),
	})
	if err == nil {
		t.Fatal("an endpoint whose check cannot compile must be refused, not served unguarded")
	}
	if p != nil {
		t.Fatal("no proxy may be returned alongside the error: returning `next` is exactly the old bug")
	}
}

// TestOversizeBody_RejectedNotTruncated: a guard that matched a prefix and
// passed the remainder would make its own cap the bypass — pad ahead of the
// method name and the rule stops seeing it.
func TestOversizeBody_RejectedNotTruncated(t *testing.T) {
	var seen string
	p, err := ProxyFactory(logging.NoOp, echoFactory(&seen)).New(&config.EndpointConfig{
		Endpoint:    "/v1/info",
		ExtraConfig: celConfig(fixedInfoRule),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Allowlisted method, but only after MaxEvaluatedBodyBytes of padding.
	padded := `{"pad":"` + strings.Repeat("A", MaxEvaluatedBodyBytes) + `","method":"info.isBootstrapped"}`
	r := &proxy.Request{Method: "POST", Path: "/v1/info", Body: io.NopCloser(strings.NewReader(padded))}

	_, err = p(context.Background(), r)
	if err == nil {
		t.Fatal("an oversize body must be refused by a guarded endpoint")
	}
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("want ErrBodyTooLarge, got %v", err)
	}
	if seen != "" {
		t.Fatal("oversize body reached the backend")
	}
}

// TestNoRule_BodyUntouched: endpoints without a check must not pay for the
// buffering, and their body must arrive exactly as sent.
func TestNoRule_BodyUntouched(t *testing.T) {
	var seen string
	p, err := ProxyFactory(logging.NoOp, echoFactory(&seen)).New(&config.EndpointConfig{
		Endpoint: "/v1/bc/C/rpc",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p(context.Background(), rpc("eth_blockNumber")); err != nil {
		t.Fatalf("unguarded endpoint must pass: %v", err)
	}
	if !strings.Contains(seen, "eth_blockNumber") {
		t.Fatalf("backend got %q", seen)
	}
}

// TestReqBodyIsDeclared pins the declaration itself. Deleting req_body from
// defaultDeclarations would silently re-break every body rule in the estate,
// and — with the fail-closed change above — take the gateway down at boot
// rather than reopen the hole, which is the outcome we want but is easier to
// diagnose from this test than from a crash loop.
func TestReqBodyIsDeclared(t *testing.T) {
	// NOT `has(req_body)` — that is what production wrote and it is invalid
	// CEL whatever the environment declares (see liveInfoRule). A plain
	// reference is what actually proves the declaration.
	if _, err := internal.NewCheckExpressionParser(logging.NoOp).Parse(
		internal.InterpretableDefinition{CheckExpression: `req_body.matches('x')`},
	); err != nil {
		t.Fatalf("req_body must be a declared CEL variable: %v", err)
	}
}

// TestProductionRuleIsRefused pins the live config's own expression. It is
// malformed CEL, so the endpoint declaring it must be refused rather than
// served unguarded — previously it compiled to nothing and the endpoint served
// every method, which is how info.peers stayed reachable on five public API
// hosts behind a rule naming the four methods it means to permit.
//
// The error does NOT stop the process. The gin router registers this one
// endpoint with a 500 handler and carries on, so the cost of a bad rule is
// that endpoint, loudly — not a crash. That is why the corrected config has to
// roll BEFORE this image.
func TestProductionRuleIsRefused(t *testing.T) {
	var seen string
	p, err := ProxyFactory(logging.NoOp, echoFactory(&seen)).New(&config.EndpointConfig{
		Endpoint:    "/v1/info",
		ExtraConfig: celConfig(liveInfoRule),
	})
	if err == nil {
		t.Fatal("the live rule does not compile; serving it unguarded is the bug")
	}
	if p != nil {
		t.Fatal("no proxy may be handed back alongside the error")
	}
}

// TestUndeclaredVariable_IsAnError covers the second silent-drop path:
// parseByKey used to swallow a Check failure at Debug and return zero
// programs with a nil error, so one mistyped variable disarmed the check
// while leaving it in the config.
func TestUndeclaredVariable_IsAnError(t *testing.T) {
	_, err := internal.NewCheckExpressionParser(logging.NoOp).ParsePre(
		[]internal.InterpretableDefinition{{CheckExpression: `req_bdoy.matches('x')`}},
	)
	if err == nil {
		t.Fatal("a check naming an undeclared variable must be an error, not a silent skip")
	}
}
