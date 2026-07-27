package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/gateway/v2/iamauth"
)

// fakeCloudAPI stands in for cloud's GET /v1/ai/account. It echoes a
// fixed account so the data-layer gate resolves a browser session exactly as
// it does in production.
func fakeCloudAPI(t *testing.T, account map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ai/account" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": account})
	}))
}

// fakeIAM stands in for the in-cluster IAM the aggregator fans out to.
func fakeIAM(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/iam/get-applications"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"data":   []map[string]any{{"owner": "admin", "name": "hanzo-cloud", "clientId": "abc123"}},
				"data2":  1,
			})
		case strings.HasPrefix(r.URL.Path, "/v1/iam/get-roles"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"data":   []map[string]any{{"owner": "admin", "name": "operators"}},
				"data2":  1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func newTestServer(cloudURL, iamURL string) *server {
	cfg := &config{
		adminOrg:    "admin",
		cloudURL:    cloudURL,
		iamInternal: iamURL,
		validator:   iamauth.NewValidator(iamauth.Config{}), // no token in tests → ErrNoToken → session path
	}
	return &server{cfg: cfg, agg: &aggregator{cfg: cfg}}
}

// request through the real gate, carrying a browser session cookie so
// sessionIdentity (the path dave's browser uses) runs.
func gatedGet(srv *server, h http.HandlerFunc, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Cookie", "hanzo_session=opaque")
	rec := httptest.NewRecorder()
	srv.gate(h)(rec, req)
	return rec
}

// The core privilege boundary: a tenant org-admin must be denied god-mode
// data at the data layer, independent of the SPA gate. This is the backend
// half of the "dave" fix.
func TestGate_DeniesTenantOrgAdmin(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "acme", "name": "dave", "isAdmin": true, "type": "normal-user"})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	for _, path := range []string{"/v1/admin/applications", "/v1/admin/roles", "/v1/admin/overview"} {
		rec := gatedGet(srv, srv.handleApplications, path)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: tenant org-admin should be 403, got %d (%s)", path, rec.Code, rec.Body.String())
		}
	}
}

// The known misconfig angle: a `hanzo` TENANT org-admin must STILL be denied
// here, because the data-layer gate is owner==AdminOrg and `hanzo` != `admin`.
// Proves the gateway admin-api is not fooled by the ai-repo
// globalAdminOrgs=admin,hanzo override.
func TestGate_DeniesHanzoTenantOrg(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "hanzo", "name": "dave", "isAdmin": true, "type": "normal-user"})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	rec := gatedGet(srv, srv.handleApplications, "/v1/admin/applications")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("hanzo tenant org-admin should be 403, got %d", rec.Code)
	}
}

func TestGate_DeniesAnonymous(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "admin", "type": "anonymous-user"})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	rec := gatedGet(srv, srv.handleApplications, "/v1/admin/applications")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous session should be 403, got %d", rec.Code)
	}
}

func TestGate_DeniesNoCookie(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "admin", "isAdmin": true})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/applications", nil)
	rec := httptest.NewRecorder()
	srv.gate(srv.handleApplications)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-cookie request should be 403, got %d", rec.Code)
	}
}

// A global admin (owner == AdminOrg) passes the gate and gets the live IAM
// applications via the unified /v1/admin/* surface — the IAM page now loads
// real data through the gated god-mode API instead of 404ing on /v1/iam/*.
func TestGate_AllowsGlobalAdmin_Applications(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "admin", "name": "root", "isAdmin": true, "type": "normal-user"})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	rec := gatedGet(srv, srv.handleApplications, "/v1/admin/applications")
	if rec.Code != http.StatusOK {
		t.Fatalf("global admin should be 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Status string           `json:"status"`
		Data   []map[string]any `json:"data"`
		Data2  int              `json:"data2"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Status != "ok" || len(env.Data) != 1 || env.Data[0]["name"] != "hanzo-cloud" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestGate_AllowsGlobalAdmin_Roles(t *testing.T) {
	cloud := fakeCloudAPI(t, map[string]any{"owner": "admin", "name": "root", "isAdmin": true, "type": "normal-user"})
	defer cloud.Close()
	iam := fakeIAM(t)
	defer iam.Close()
	srv := newTestServer(cloud.URL, iam.URL)

	rec := gatedGet(srv, srv.handleRoles, "/v1/admin/roles")
	if rec.Code != http.StatusOK {
		t.Fatalf("global admin should be 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}
