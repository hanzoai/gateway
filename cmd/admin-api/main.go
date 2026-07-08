// admin-api is the god-mode backend for the Hanzo Operator console
// (admin.hanzo.ai). It is the ONE analytics layer: an aggregator periodically
// pulls every product's identity, usage and health into a dedicated `admin`
// database inside the ZAP-native Hanzo Datastore, and a small read API serves
// that aggregate to the operator SPA under /v1/admin/*.
//
// Two orthogonal concerns, one binary:
//
//  1. aggregate — sources (IAM, platform, commerce) → datastore. A background
//     ticker plus an on-demand POST /v1/admin/sync.
//  2. serve — /v1/admin/* reads over the `admin` db. Every request is gated to
//     a Hanzo superadmin (owner == AdminOrg), enforced at the DATA LAYER here
//     independently of the ingress admin-guard ForwardAuth. Defense in depth:
//     a request that slips past the edge still cannot read god-mode data
//     without a superadmin session or JWT. Fail-closed.
//
// Identity is resolved exactly like the rest of the platform: a Bearer/Basic
// JWT validated through iamauth, or the first-party session cookie minted by
// cloud (forwarded to /v1/get-account). Either way the predicate is the
// same single fact — owner == AdminOrg — the same one admin-guard enforces at
// the edge.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/gateway/v2/iamauth"
)

type config struct {
	addr     string
	adminOrg string

	// Datastore (the analytics layer).
	dsAddr     string
	dsUser     string
	dsPassword string
	dsDatabase string

	// Source backends for the aggregator.
	iamInternal string
	iamClientID string
	iamSecret   string
	cloudURL    string // cloud: session check (/v1/get-account)
	commerceURL string
	commerceTok string
	platformURL string
	platformTok string

	syncInterval time.Duration

	validator *iamauth.Validator
}

func loadConfig() *config {
	return &config{
		addr:     envOr("ADMIN_API_ADDR", ":8080"),
		adminOrg: envOr("IAM_ADMIN_ORG", "admin"),

		dsAddr:     envOr("DATASTORE_ADDR", "datastore.hanzo.svc.cluster.local:9000"),
		dsUser:     envOr("DATASTORE_USER", "hanzo"),
		dsPassword: os.Getenv("DATASTORE_PASSWORD"),
		dsDatabase: envOr("DATASTORE_DB", "admin"),

		iamInternal: strings.TrimRight(envOr("IAM_INTERNAL_URL", "http://iam.hanzo.svc.cluster.local"), "/"),
		iamClientID: os.Getenv("IAM_CLIENT_ID"),
		iamSecret:   os.Getenv("IAM_CLIENT_SECRET"),
		cloudURL:    strings.TrimRight(envOr("CLOUD_API_URL", "http://cloud.hanzo.svc.cluster.local:8000"), "/"),
		commerceURL: strings.TrimRight(envOr("COMMERCE_URL", "http://commerce.hanzo.svc.cluster.local:8001"), "/"),
		commerceTok: os.Getenv("COMMERCE_SERVICE_TOKEN"),
		platformURL: strings.TrimRight(envOr("PLATFORM_URL", "http://platform.hanzo.svc.cluster.local:4000"), "/"),
		platformTok: firstEnv("PLATFORM_SERVICE_TOKEN", "PAAS_SERVICE_TOKEN"),

		syncInterval: envDuration("ADMIN_SYNC_INTERVAL", 5*time.Minute),

		validator: iamauth.NewValidator(iamauth.ConfigFromEnv()),
	}
}

func main() {
	cfg := loadConfig()

	store, err := openStore(cfg)
	if err != nil {
		log.Fatalf("admin-api: datastore connect: %v", err)
	}
	defer store.Close()

	if err := store.bootstrap(context.Background()); err != nil {
		log.Fatalf("admin-api: schema bootstrap: %v", err)
	}

	agg := &aggregator{cfg: cfg, store: store}

	// Aggregate on boot (best-effort) then on a ticker, so the cockpit is never
	// empty for long and never blocks serving on a slow source.
	go agg.loop(context.Background())

	srv := &server{cfg: cfg, store: store, agg: agg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/admin/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /v1/admin/me", srv.gate(srv.handleMe))
	mux.HandleFunc("GET /v1/admin/overview", srv.gate(srv.handleOverview))
	mux.HandleFunc("GET /v1/admin/orgs", srv.gate(srv.handleOrgs))
	mux.HandleFunc("GET /v1/admin/users", srv.gate(srv.handleUsers))
	mux.HandleFunc("GET /v1/admin/usage", srv.gate(srv.handleUsage))
	mux.HandleFunc("GET /v1/admin/products", srv.gate(srv.handleProducts))
	mux.HandleFunc("GET /v1/admin/audit", srv.gate(srv.handleAudit))
	mux.HandleFunc("GET /v1/admin/applications", srv.gate(srv.handleApplications))
	mux.HandleFunc("GET /v1/admin/roles", srv.gate(srv.handleRoles))
	mux.HandleFunc("POST /v1/admin/sync", srv.gate(srv.handleSync))

	h := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("admin-api listening on %s (adminOrg=%q datastore=%s/%s sync=%s)",
		cfg.addr, cfg.adminOrg, cfg.dsAddr, cfg.dsDatabase, cfg.syncInterval)
	log.Fatal(h.ListenAndServe())
}

// ---- envelope + identity --------------------------------------------------

// identity is the resolved caller, attached to the request context by gate().
type identity struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	DisplayName   string `json:"displayName"`
	IsGlobalAdmin bool   `json:"isGlobalAdmin"`
}

type ctxKey int

const identityKey ctxKey = 0

func identityOf(r *http.Request) identity {
	if v, ok := r.Context().Value(identityKey).(identity); ok {
		return v
	}
	return identity{}
}

// envelope mirrors the casibase wire shape the operator SPA already speaks:
// { status, msg, data, data2 }. data2 carries the list total for paged reads.
type envelope struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   any    `json:"data"`
	Data2  any    `json:"data2,omitempty"`
}

func writeOK(w http.ResponseWriter, data any, total ...any) {
	e := envelope{Status: "ok", Data: data}
	if len(total) > 0 {
		e.Data2 = total[0]
	}
	writeJSON(w, http.StatusOK, e)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, envelope{Status: "error", Msg: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- small env helpers ----------------------------------------------------

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func envDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if p, err := time.ParseDuration(v); err == nil {
			return p
		}
	}
	return d
}

func atoiOr(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}
