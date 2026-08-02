// Copyright © 2026 Hanzo AI. Apache-2.0 License.

//go:build !legacy
// +build !legacy

package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	gateway "github.com/hanzoai/gateway/v2"
)

// TestHealthApp_TableIsInTheBinary is the proof the estate has twice shipped
// without.
//
// A typed-op table can be present in the source, compile, pass every test that
// mounts it directly, and still be ABSENT from the binary that ships — because
// nothing on the binary's own import path ever registers it. A green build says
// nothing about that, and neither does a Mount test: both can be satisfied by a
// declaration no listener ever sees.
//
// So this boots the app the BINARY boots — buildHealthApp, called by main from
// this package — and reads the LIVE router off it. If a future edit drops the
// registration, adds a route without typing it, or makes the ops unreachable
// from cmd/, the counts move and this fails.
func TestHealthApp_TableIsInTheBinary(t *testing.T) {
	d := buildHealthApp().Declaration()

	// 3 routes: the two typed probes plus the /metrics hatch.
	// 2 ops:    the probes. /metrics is text, so it is deliberately untyped —
	//           see gateway.MountMetrics for why, and note that the gap between
	//           these two numbers IS the count of escape hatches.
	const wantRoutes, wantOps = 3, 2
	if len(d.Routes) != wantRoutes {
		t.Errorf("health app routes: got %d want %d — %+v", len(d.Routes), wantRoutes, d.Routes)
	}
	if len(d.Ops) != wantOps {
		t.Errorf("health app typed ops: got %d want %d — %+v", len(d.Ops), wantOps, d.Ops)
	}
	if hatches := len(d.Routes) - len(d.Ops); hatches != 1 {
		t.Errorf("untyped routes: got %d want 1 (/metrics, and nothing else)", hatches)
	}
}

// TestHealthApp_ProbesAnswer drives the routes rather than counting them: the
// listener k8s hits must actually answer, with the one shape probes.go states.
func TestHealthApp_ProbesAnswer(t *testing.T) {
	app := buildHealthApp()

	for path, want := range map[string]string{"/healthz": "ok", "/readyz": "ready"} {
		resp, err := app.Fiber().Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d want 200", path, resp.StatusCode)
		}
		var out gateway.ProbeOut
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("%s decode: %v", path, err)
		}
		if out.Status != want || out.Service != gateway.ServiceName {
			t.Fatalf("%s: got %+v want status=%q service=%q", path, out, want, gateway.ServiceName)
		}
	}

	resp, err := app.Fiber().Test(httptest.NewRequest("GET", "/metrics", nil))
	if err != nil {
		t.Fatalf("/metrics: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("/metrics: status %d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4" {
		t.Fatalf("/metrics content-type: got %q — the hatch exists because this is NOT JSON", ct)
	}
}
