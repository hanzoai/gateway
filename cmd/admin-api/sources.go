package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// aggregator is the write side: it pulls every product's identity, usage and
// health into the `admin` datastore. Each source is independent and
// best-effort — a source that errors records its failure in admin.sync_runs and
// leaves the others (and the last good data) intact. Never fabricates.
type aggregator struct {
	cfg   *config
	store *store

	mu      sync.Mutex
	running bool
	lastErr string
}

func (a *aggregator) loop(ctx context.Context) {
	a.syncOnce(ctx)
	t := time.NewTicker(a.cfg.syncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.syncOnce(ctx)
		}
	}
}

// syncOnce runs all sources once. Guarded so overlapping ticks/sync calls don't
// pile up.
func (a *aggregator) syncOnce(parent context.Context) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return
	}
	a.running = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.running = false; a.mu.Unlock() }()

	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()

	orgs := a.syncIAM(ctx)
	a.syncPlatform(ctx)
	a.syncCommerce(ctx, orgs)
}

// ---- IAM: organizations + users ------------------------------------------

func (a *aggregator) iamHeaders() map[string]string {
	h := map[string]string{"Accept": "application/json"}
	if a.cfg.iamClientID != "" && a.cfg.iamSecret != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(a.cfg.iamClientID + ":" + a.cfg.iamSecret))
		h["Authorization"] = "Basic " + basic
	}
	return h
}

func (a *aggregator) syncIAM(ctx context.Context) []string {
	var orgNames []string

	// Organizations.
	var orgEnv struct {
		Data []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
			CreatedTime string `json:"createdTime"`
		} `json:"data"`
	}
	err := httpGetJSON(ctx, a.cfg.iamInternal+"/v1/iam/get-organizations?pageSize=1000&p=1", a.iamHeaders(), &orgEnv)
	if err != nil {
		a.store.recordSync(ctx, "iam:orgs", false, 0, err.Error())
	} else {
		rows := make([]orgRow, 0, len(orgEnv.Data))
		for _, o := range orgEnv.Data {
			orgNames = append(orgNames, o.Name)
			rows = append(rows, orgRow{Org: o.Name, Display: nz(o.DisplayName, o.Name), Source: "iam", Created: parseTime(o.CreatedTime)})
		}
		if err := a.store.upsertOrgs(ctx, rows); err != nil {
			a.store.recordSync(ctx, "iam:orgs", false, 0, err.Error())
		} else {
			a.store.recordSync(ctx, "iam:orgs", true, len(rows), "")
		}
	}

	// Users across all orgs.
	var userEnv struct {
		Data []struct {
			Owner          string `json:"owner"`
			Name           string `json:"name"`
			Email          string `json:"email"`
			DisplayName    string `json:"displayName"`
			IsAdmin        bool   `json:"isAdmin"`
			Tag            string `json:"tag"`
			IsForbidden    bool   `json:"isForbidden"`
			CreatedTime    string `json:"createdTime"`
			LastSigninTime string `json:"lastSigninTime"`
		} `json:"data"`
	}
	err = httpGetJSON(ctx, a.cfg.iamInternal+"/v1/iam/get-global-users?pageSize=5000&p=1", a.iamHeaders(), &userEnv)
	if err != nil {
		a.store.recordSync(ctx, "iam:users", false, 0, err.Error())
		return orgNames
	}
	rows := make([]userRow, 0, len(userEnv.Data))
	for _, u := range userEnv.Data {
		rows = append(rows, userRow{
			Org: u.Owner, Name: u.Name, Email: u.Email, Display: nz(u.DisplayName, u.Name),
			IsAdmin: b2u(u.IsAdmin), IsGlobalAdmin: b2u(u.Owner == a.cfg.adminOrg),
			Tag: u.Tag, Forbidden: b2u(u.IsForbidden),
			Created: parseTime(u.CreatedTime), LastSignin: parseTime(u.LastSigninTime),
		})
	}
	if err := a.store.upsertUsers(ctx, rows); err != nil {
		a.store.recordSync(ctx, "iam:users", false, 0, err.Error())
	} else {
		a.store.recordSync(ctx, "iam:users", true, len(rows), "")
	}
	return orgNames
}

// ---- platform: deployed apps + clusters ----------------------------------

func (a *aggregator) syncPlatform(ctx context.Context) {
	if a.cfg.platformURL == "" || a.cfg.platformTok == "" {
		a.store.recordSync(ctx, "platform:apps", false, 0, "platform url/token not configured")
		return
	}
	// The control plane's apps table is flexible across versions; decode
	// permissively and map common field spellings.
	var raw json.RawMessage
	if err := httpGetJSON(ctx, a.cfg.platformURL+"/v1/apps", map[string]string{
		"Accept": "application/json", "Authorization": "Bearer " + a.cfg.platformTok,
	}, &raw); err != nil {
		a.store.recordSync(ctx, "platform:apps", false, 0, err.Error())
		return
	}
	apps := flattenList(raw, "apps", "data", "items")
	rows := make([]productRow, 0, len(apps))
	for _, m := range apps {
		name := firstStr(m, "name", "app", "slug", "id")
		if name == "" {
			continue
		}
		declared := firstStr(m, "declaredTag", "declared_tag", "declared", "desiredTag")
		running := firstStr(m, "runningTag", "running_tag", "running", "image", "currentTag")
		health := normHealth(firstStr(m, "health", "status", "state"))
		drift := boolish(m, "drift") || (declared != "" && running != "" && !strings.Contains(running, declared) && declared != running)
		rows = append(rows, productRow{
			Name: name, Kind: "app", Org: firstStr(m, "org", "organization", "owner"),
			Cluster:     firstStr(m, "cluster", "target", "clusterName"),
			DeclaredTag: declared, RunningTag: running, Health: health, Drift: b2u(drift),
			Updated: time.Now(),
		})
	}
	if err := a.store.upsertProducts(ctx, rows); err != nil {
		a.store.recordSync(ctx, "platform:apps", false, 0, err.Error())
		return
	}
	a.store.recordSync(ctx, "platform:apps", true, len(rows), "")
}

// ---- commerce: per-org credits + AI spend/tokens from the ledger ----------

func (a *aggregator) syncCommerce(ctx context.Context, orgs []string) {
	if a.cfg.commerceURL == "" || a.cfg.commerceTok == "" {
		a.store.recordSync(ctx, "commerce:ledger", false, 0, "commerce url/token not configured")
		return
	}
	if len(orgs) == 0 {
		orgs = []string{a.cfg.adminOrg, "hanzo"}
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var usage []usageRow
	var n int
	var firstErr string

	for _, org := range orgs {
		hdr := map[string]string{
			"Accept": "application/json", "Authorization": "Bearer " + a.cfg.commerceTok, "X-Org-Id": org,
		}
		// Current balance → credits_cents snapshot for today.
		var bal struct {
			Balance int64 `json:"balance"`
		}
		if err := httpGetJSON(ctx, a.cfg.commerceURL+"/v1/billing/balance?user="+url.QueryEscape(org), hdr, &bal); err == nil {
			usage = append(usage, usageRow{Day: today, Org: org, Product: "commerce", Metric: "credits_cents", Value: float64(bal.Balance)})
		} else if firstErr == "" {
			firstErr = err.Error()
		}

		// Usage ledger → spend_cents / tokens / requests bucketed by day & product.
		var u struct {
			Usage []struct {
				Amount    int64  `json:"amount"`
				CreatedAt string `json:"createdAt"`
				Metadata  struct {
					Model            string `json:"model"`
					Provider         string `json:"provider"`
					PromptTokens     int64  `json:"promptTokens"`
					CompletionTokens int64  `json:"completionTokens"`
				} `json:"metadata"`
			} `json:"usage"`
		}
		if err := httpGetJSON(ctx, a.cfg.commerceURL+"/v1/billing/usage?user="+url.QueryEscape(org), hdr, &u); err != nil {
			if firstErr == "" {
				firstErr = err.Error()
			}
			continue
		}
		// Aggregate per (day) for this org under the 'ai' product line.
		type k struct{ day time.Time }
		spend := map[time.Time]float64{}
		toks := map[time.Time]float64{}
		reqs := map[time.Time]float64{}
		for _, t := range u.Usage {
			d := parseTime(t.CreatedAt).UTC().Truncate(24 * time.Hour)
			if d.IsZero() {
				d = today
			}
			spend[d] += float64(t.Amount)
			toks[d] += float64(t.Metadata.PromptTokens + t.Metadata.CompletionTokens)
			reqs[d]++
		}
		for d, v := range spend {
			usage = append(usage, usageRow{Day: d, Org: org, Product: "ai", Metric: "spend_cents", Value: v})
		}
		for d, v := range toks {
			usage = append(usage, usageRow{Day: d, Org: org, Product: "ai", Metric: "tokens", Value: v})
		}
		for d, v := range reqs {
			usage = append(usage, usageRow{Day: d, Org: org, Product: "ai", Metric: "requests", Value: v})
		}
		n++
	}
	if err := a.store.upsertUsage(ctx, usage); err != nil {
		a.store.recordSync(ctx, "commerce:ledger", false, 0, err.Error())
		return
	}
	a.store.recordSync(ctx, "commerce:ledger", firstErr == "", n, firstErr)
}

// liveAudit fetches recent IAM audit records on demand (not stored — always
// fresh). Returns the casibase records slice.
func (a *aggregator) liveAudit(ctx context.Context, org string, pageSize int) ([]map[string]any, int, error) {
	if org == "" {
		org = a.cfg.adminOrg
	}
	var env struct {
		Data  []map[string]any `json:"data"`
		Data2 json.Number      `json:"data2"`
	}
	u := fmt.Sprintf("%s/v1/iam/get-records?owner=%s&pageSize=%d&p=1&sortField=createdTime&sortOrder=descend",
		a.cfg.iamInternal, url.QueryEscape(org), pageSize)
	if err := httpGetJSON(ctx, u, a.iamHeaders(), &env); err != nil {
		return nil, 0, err
	}
	total := len(env.Data)
	if n, err := env.Data2.Int64(); err == nil && n > 0 {
		total = int(n)
	}
	return env.Data, total, nil
}

// liveApplications fetches IAM OAuth applications on demand (not stored —
// always fresh). IAM redacts secrets server-side (GetMaskedApplications) and
// the caller is gated to a superadmin upstream, so this is a god-mode read of
// the global application registry. owner defaults to the AdminOrg, which owns
// the platform applications.
func (a *aggregator) liveApplications(ctx context.Context, owner string, pageSize int) ([]map[string]any, int, error) {
	if owner == "" {
		owner = a.cfg.adminOrg
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	var env struct {
		Data  []map[string]any `json:"data"`
		Data2 json.Number      `json:"data2"`
	}
	u := fmt.Sprintf("%s/v1/iam/get-applications?owner=%s&pageSize=%d&p=1",
		a.cfg.iamInternal, url.QueryEscape(owner), pageSize)
	if err := httpGetJSON(ctx, u, a.iamHeaders(), &env); err != nil {
		return nil, 0, err
	}
	total := len(env.Data)
	if n, err := env.Data2.Int64(); err == nil && n > 0 {
		total = int(n)
	}
	return env.Data, total, nil
}

// liveRoles fetches IAM roles for an org on demand (not stored — always fresh).
// owner defaults to the AdminOrg. Gated to a superadmin upstream.
func (a *aggregator) liveRoles(ctx context.Context, owner string, pageSize int) ([]map[string]any, int, error) {
	if owner == "" {
		owner = a.cfg.adminOrg
	}
	if pageSize <= 0 {
		pageSize = 100
	}
	var env struct {
		Data  []map[string]any `json:"data"`
		Data2 json.Number      `json:"data2"`
	}
	u := fmt.Sprintf("%s/v1/iam/get-roles?owner=%s&pageSize=%d&p=1",
		a.cfg.iamInternal, url.QueryEscape(owner), pageSize)
	if err := httpGetJSON(ctx, u, a.iamHeaders(), &env); err != nil {
		return nil, 0, err
	}
	total := len(env.Data)
	if n, err := env.Data2.Int64(); err == nil && n > 0 {
		total = int(n)
	}
	return env.Data, total, nil
}

// ---- http + parsing helpers ----------------------------------------------

var httpClient = &http.Client{Timeout: 30 * time.Second}

func httpGetJSON(ctx context.Context, u string, headers map[string]string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d: %s", shortURL(u), resp.StatusCode, truncate(body, 180))
	}
	if dest == nil {
		return nil
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("decode %s: %w", shortURL(u), err)
	}
	return nil
}

// flattenList accepts either a bare JSON array or an object with the payload
// under one of the given keys (or a casibase {data:[...]} envelope).
func flattenList(raw json.RawMessage, keys ...string) []map[string]any {
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) == nil && arr != nil {
		return arr
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			if json.Unmarshal(v, &arr) == nil {
				return arr
			}
		}
	}
	return nil
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%v", t)
			}
		}
	}
	return ""
}

func boolish(m map[string]any, key string) bool {
	switch t := m[key].(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "drift" || t == "yes"
	case float64:
		return t != 0
	}
	return false
}

func normHealth(s string) string {
	switch strings.ToLower(s) {
	case "green", "healthy", "ok", "running", "ready", "active", "synced":
		return "green"
	case "yellow", "degraded", "progressing", "pending", "warning":
		return "yellow"
	case "red", "unhealthy", "failed", "error", "crashloopbackoff", "down", "missing":
		return "red"
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func shortURL(u string) string {
	if i := strings.Index(u, "?"); i > 0 {
		return u[:i]
	}
	return u
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

func init() { _ = log.Flags() }
