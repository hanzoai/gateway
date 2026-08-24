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

	"github.com/hanzoai/gateway/v2/iam"
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
	orgs, err := a.iamOrgs(ctx)
	if err != nil {
		a.store.recordSync(ctx, "iam:orgs", false, 0, err.Error())
		// Without the tenant list there is nothing to read people out of, so the
		// user sync has no input rather than an empty answer. Say so.
		a.store.recordSync(ctx, "iam:users", false, 0, "organizations unavailable: "+err.Error())
		return nil
	}
	orgNames := make([]string, 0, len(orgs))
	rows := make([]orgRow, 0, len(orgs))
	for _, o := range orgs {
		orgNames = append(orgNames, o.Name)
		rows = append(rows, orgRow{Org: o.Name, Display: nz(o.DisplayName, o.Name), Source: "iam", Created: parseTime(o.CreatedTime)})
	}
	if err := a.store.upsertOrgs(ctx, rows); err != nil {
		a.store.recordSync(ctx, "iam:orgs", false, 0, err.Error())
	} else {
		a.store.recordSync(ctx, "iam:orgs", true, len(rows), "")
	}

	a.syncUsers(ctx, orgNames)
	return orgNames
}

// iamOrg is the slice of an organization this dashboard shows.
type iamOrg struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	CreatedTime string `json:"createdTime"`
}

// iamOrgs reads every organization the credential may see.
//
// The collection is cursor-paged and caps a page at 100, so one request is a
// PAGE and never the registry: this follows the cursor until the answer stops
// carrying one. Reading only the first page would silently shrink the dashboard
// to its first hundred tenants, which looks exactly like a small estate.
func (a *aggregator) iamOrgs(ctx context.Context) ([]iamOrg, error) {
	const page = 100 // the collection's own ceiling; asking for more yields 100
	var out []iamOrg
	cursor := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(page)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var body struct {
			Organizations []iamOrg `json:"organizations"`
			Cursor        string   `json:"cursor"`
		}
		if err := httpGetJSON(ctx, a.cfg.iamInternal+iam.Organizations+"?"+q.Encode(), a.iamHeaders(), &body); err != nil {
			return nil, err
		}
		out = append(out, body.Organizations...)
		if body.Cursor == "" || body.Cursor == cursor {
			return out, nil
		}
		cursor = body.Cursor
	}
}

// iamUser is the slice of a person this dashboard shows.
type iamUser struct {
	Owner          string `json:"owner"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	DisplayName    string `json:"displayName"`
	IsAdmin        bool   `json:"isAdmin"`
	Tag            string `json:"tag"`
	IsForbidden    bool   `json:"isForbidden"`
	CreatedTime    string `json:"createdTime"`
	LastSigninTime string `json:"lastSigninTime"`
}

// syncUsers reads the people in each organization.
//
// The user collection is owner-scoped and has no ownerless listing, so "everyone"
// is the tenant list walked one org at a time. A tenant that refuses or errors is
// COUNTED and named in the sync record rather than dropped: an aggregator that
// swallowed a refusal would show a shrunken estate as a healthy one, and this
// table is what an operator reads to decide whether they are looking at
// everything.
func (a *aggregator) syncUsers(ctx context.Context, orgs []string) {
	rows := make([]userRow, 0, len(orgs)*8)
	var failed []string
	for _, org := range orgs {
		people, err := a.iamUsers(ctx, org)
		if err != nil {
			failed = append(failed, org)
			continue
		}
		for _, u := range people {
			rows = append(rows, userRow{
				Org: u.Owner, Name: u.Name, Email: u.Email, Display: nz(u.DisplayName, u.Name),
				IsAdmin: b2u(u.IsAdmin), IsGlobalAdmin: b2u(u.Owner == a.cfg.adminOrg),
				Tag: u.Tag, Forbidden: b2u(u.IsForbidden),
				Created: parseTime(u.CreatedTime), LastSignin: parseTime(u.LastSigninTime),
			})
		}
	}
	if err := a.store.upsertUsers(ctx, rows); err != nil {
		a.store.recordSync(ctx, "iam:users", false, 0, err.Error())
		return
	}
	if len(failed) > 0 {
		a.store.recordSync(ctx, "iam:users", false, len(rows),
			fmt.Sprintf("%d of %d organizations unread: %s", len(failed), len(orgs), strings.Join(clip(failed, 10), ", ")))
		return
	}
	a.store.recordSync(ctx, "iam:users", true, len(rows), "")
}

// iamUsers reads one organization's people, following `offset` until the page
// stops advancing on the total the collection reports.
func (a *aggregator) iamUsers(ctx context.Context, org string) ([]iamUser, error) {
	const page = 500
	var out []iamUser
	for {
		q := url.Values{
			"owner":  {org},
			"limit":  {fmt.Sprint(page)},
			"offset": {fmt.Sprint(len(out))},
		}
		var body struct {
			Users []iamUser `json:"users"`
			Total int       `json:"total"`
		}
		if err := httpGetJSON(ctx, a.cfg.iamInternal+iam.Users+"?"+q.Encode(), a.iamHeaders(), &body); err != nil {
			return nil, err
		}
		out = append(out, body.Users...)
		if len(body.Users) == 0 || len(out) >= body.Total {
			return out, nil
		}
	}
}

// clip returns at most n of xs, so one bad sync cannot write an unbounded
// sentence into the sync record.
func clip(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(xs[:n:n], "…")
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

// iamList is IAM's list envelope. The count is total; data2 is the legacy
// untyped slot the rename vacates — read second only until IAM's rename is
// deployed everywhere, then the fallback is deleted.
// liveList fetches one owner-scoped IAM collection on demand (not stored —
// always fresh) and returns the rows plus the total.
//
// The collection answers the list ITSELF, under a key named for the resource,
// with `total` beside it where the resource counts — nothing is wrapped, and a
// refusal is a real 4xx that httpGetJSON turns into an error. key is that name,
// which is the only thing that varies between these reads.
func (a *aggregator) liveList(ctx context.Context, path, owner, key string, size int) ([]map[string]any, int, error) {
	if owner == "" {
		owner = a.cfg.adminOrg
	}
	u := a.cfg.iamInternal + path + "?owner=" + url.QueryEscape(owner)
	var body map[string]json.RawMessage
	if err := httpGetJSON(ctx, u, a.iamHeaders(), &body); err != nil {
		return nil, 0, err
	}
	var rows []map[string]any
	if raw, ok := body[key]; ok {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, 0, fmt.Errorf("decode %s: %w", key, err)
		}
	}
	total := len(rows)
	if raw, ok := body["total"]; ok {
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			if v, err := n.Int64(); err == nil && int(v) > total {
				total = int(v)
			}
		}
	}
	// These collections answer an owner WHOLE — an org's audit trail is every
	// entry it has, newest first — so the caller's page is applied HERE, the only
	// place that now holds one. The total stays the count of everything, because
	// that is what it is.
	if size > 0 && len(rows) > size {
		rows = rows[:size]
	}
	return rows, total, nil
}

// liveAudit fetches an org's IAM audit trail on demand, newest first.
func (a *aggregator) liveAudit(ctx context.Context, org string, size int) ([]map[string]any, int, error) {
	return a.liveList(ctx, iam.AuditLogs, org, "auditLogs", size)
}

// liveApplications fetches IAM OAuth applications on demand (not stored —
// always fresh). IAM redacts secrets server-side and the caller is gated to a
// superadmin upstream, so this is a god-mode read of the application registry.
// owner defaults to the AdminOrg, which owns the platform applications.
func (a *aggregator) liveApplications(ctx context.Context, owner string, size int) ([]map[string]any, int, error) {
	return a.liveList(ctx, iam.Applications, owner, "applications", size)
}

// liveRoles fetches IAM roles for an org on demand (not stored — always fresh).
// owner defaults to the AdminOrg. Gated to a superadmin upstream.
func (a *aggregator) liveRoles(ctx context.Context, owner string, size int) ([]map[string]any, int, error) {
	return a.liveList(ctx, iam.Roles, owner, "roles", size)
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
