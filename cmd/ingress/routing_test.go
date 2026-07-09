package main

// Proves the agent-skills serve-point recipe at the ingress layer: a
// `/.well-known/agent-skills` backend wins the longest-prefix match over the
// site's `/` catch-all and reaches the cloud backend, while every other path
// still reaches the site — and the ORIGINAL Host is preserved to the cloud
// backend, which is what lets cloud white-label a Lux/Zoo site correctly.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentSkillsIngressRouting(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "SITE")
	}))
	defer site.Close()

	var gotHost string
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host // the ingress must forward the ORIGINAL Host (white-label key)
		io.WriteString(w, "CLOUD")
	}))
	defer cloud.Close()

	cfg := &Config{Routes: []HostRoute{
		{Host: "console.hanzo.ai", Backends: []PathBackend{
			{Path: "/.well-known/agent-skills", URL: cloud.URL},
			{Path: "/", URL: site.URL},
		}},
		{Host: "cloud.lux.network", Backends: []PathBackend{
			{Path: "/.well-known/agent-skills", URL: cloud.URL},
			{Path: "/", URL: site.URL},
		}},
	}}
	r := newRouter(cfg)

	cases := []struct {
		host, path, wantBody, wantHost string
	}{
		// discovery path → cloud, Host preserved (hanzo brand site)
		{"console.hanzo.ai", "/.well-known/agent-skills/index.json", "CLOUD", "console.hanzo.ai"},
		{"console.hanzo.ai", "/.well-known/agent-skills/ai_models/SKILL.md", "CLOUD", "console.hanzo.ai"},
		// everything else → the site
		{"console.hanzo.ai", "/", "SITE", ""},
		{"console.hanzo.ai", "/dashboard", "SITE", ""},
		// OIDC discovery must NOT be captured by the specific agent-skills prefix
		{"console.hanzo.ai", "/.well-known/openid-configuration", "SITE", ""},
		// white-label: a Lux host forwards Host=cloud.lux.network so cloud serves Lux
		{"cloud.lux.network", "/.well-known/agent-skills/index.json", "CLOUD", "cloud.lux.network"},
	}
	for _, tc := range cases {
		gotHost = ""
		req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if body := rec.Body.String(); body != tc.wantBody {
			t.Errorf("%s%s → body %q, want %q", tc.host, tc.path, body, tc.wantBody)
		}
		if tc.wantHost != "" && gotHost != tc.wantHost {
			t.Errorf("%s%s → cloud saw Host %q, want %q (white-label breaks)", tc.host, tc.path, gotHost, tc.wantHost)
		}
	}
}
