package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type server struct {
	cfg   *config
	store *store
	agg   *aggregator

	mu    sync.Mutex
	cache map[string]cachedID // cookie-hash → identity (60s TTL)
}

type cachedID struct {
	id  identity
	exp time.Time
}

// gate is the DATA-LAYER superadmin enforcement, independent of the ingress
// admin-guard ForwardAuth. The predicate is the single platform fact: the
// caller's org equals AdminOrg. Resolved from a Bearer/Basic JWT (the API path)
// or the cloud first-party session cookie (the browser path). Fail-closed:
// no superadmin identity → 403, never god-mode data.
func (s *server) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.authenticate(r)
		if !ok {
			writeErr(w, http.StatusForbidden, "superadmin required")
			return
		}
		ctx := context.WithValue(r.Context(), identityKey, id)
		next(w, r.WithContext(ctx))
	}
}

func (s *server) authenticate(r *http.Request) (identity, bool) {
	// (1) JWT (Bearer/Basic) — carries `owner` directly.
	if claims, err := s.cfg.validator.Verify(r.Header); err == nil && claims != nil {
		if claims.Owner == s.cfg.adminOrg {
			return identity{
				Owner: claims.Owner, Name: claims.Name, Email: claims.Email,
				DisplayName: claims.Name, IsGlobalAdmin: true,
			}, true
		}
		return identity{}, false // a valid non-admin token is a definitive deny
	}
	// (2) cloud session cookie → /v1/ai/account.
	return s.sessionIdentity(r)
}

func (s *server) sessionIdentity(r *http.Request) (identity, bool) {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return identity{}, false
	}
	key := hashStr(cookie)
	if id, ok := s.cacheGet(key); ok {
		return id, id.Owner == s.cfg.adminOrg
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.cloudURL+"/v1/ai/account", nil)
	if err != nil {
		return identity{}, false
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return identity{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return identity{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Status string `json:"status"`
		Data   struct {
			Owner         string `json:"owner"`
			Name          string `json:"name"`
			Email         string `json:"email"`
			DisplayName   string `json:"displayName"`
			Type          string `json:"type"`
			IsForbidden   bool   `json:"isForbidden"`
			IsGlobalAdmin bool   `json:"isGlobalAdmin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return identity{}, false
	}
	d := env.Data
	if d.Type == "anonymous-user" || d.IsForbidden {
		return identity{}, false
	}
	if d.Owner != s.cfg.adminOrg {
		return identity{}, false
	}
	id := identity{Owner: d.Owner, Name: d.Name, Email: d.Email, DisplayName: nz(d.DisplayName, d.Name), IsGlobalAdmin: true}
	s.cachePut(key, id)
	return id, true
}

// ---- handlers -------------------------------------------------------------

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeOK(w, identityOf(r))
}

func (s *server) handleOverview(w http.ResponseWriter, r *http.Request) {
	o, err := s.store.overview(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, o)
}

func (s *server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.listOrgs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, rows, len(rows))
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiOr(q.Get("p"), 1)
	size := atoiOr(q.Get("pageSize"), 50)
	if size < 1 || size > 1000 {
		size = 50
	}
	if page < 1 {
		page = 1
	}
	rows, total, err := s.store.listUsers(r.Context(), strings.TrimSpace(q.Get("q")), q.Get("org"), size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, rows, total)
}

func (s *server) handleUsage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	to := time.Now()
	from := to.AddDate(0, 0, -30)
	if v := parseTime(q.Get("from")); !v.IsZero() {
		from = v
	}
	if v := parseTime(q.Get("to")); !v.IsZero() {
		to = v
	}
	d, err := s.store.usage(r.Context(), q.Get("org"), from, to)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, d)
}

func (s *server) handleProducts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.listProducts(r.Context(), r.URL.Query().Get("kind"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, rows, len(rows))
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := atoiOr(q.Get("pageSize"), 100)
	recs, total, err := s.agg.liveAudit(r.Context(), q.Get("org"), size)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"createdTime":  rec["createdTime"],
			"organization": rec["organization"],
			"user":         rec["user"],
			"clientIp":     rec["clientIp"],
			"method":       rec["method"],
			"action":       rec["action"],
			"requestUri":   rec["requestUri"],
		})
	}
	writeOK(w, out, total)
}

func (s *server) handleApplications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := atoiOr(q.Get("pageSize"), 100)
	rows, total, err := s.agg.liveApplications(r.Context(), q.Get("owner"), size)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, rows, total)
}

func (s *server) handleRoles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := atoiOr(q.Get("pageSize"), 100)
	rows, total, err := s.agg.liveRoles(r.Context(), q.Get("owner"), size)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, rows, total)
}

func (s *server) handleSync(w http.ResponseWriter, r *http.Request) {
	go s.agg.syncOnce(context.Background())
	writeOK(w, map[string]any{"started": true})
}

// ---- identity cache -------------------------------------------------------

func (s *server) cacheGet(key string) (identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		return identity{}, false
	}
	c, ok := s.cache[key]
	if !ok || time.Now().After(c.exp) {
		return identity{}, false
	}
	return c.id, true
}

func (s *server) cachePut(key string, id identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]cachedID{}
	}
	if len(s.cache) > 4096 {
		s.cache = map[string]cachedID{}
	}
	s.cache[key] = cachedID{id: id, exp: time.Now().Add(60 * time.Second)}
}

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
