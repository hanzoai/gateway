package main

import (
	"context"
	"time"
)

// Output shapes — the exact JSON the operator SPA consumes under /v1/admin/*.

type sourceStat struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Rows  int    `json:"rows"`
	Error string `json:"error"`
	At    string `json:"at"`
}

type overviewData struct {
	Orgs           int          `json:"orgs"`
	Users          int          `json:"users"`
	Products       int          `json:"products"`
	ActiveProducts int          `json:"activeProducts"`
	Drift          int          `json:"drift"`
	SpendCents30d  int64        `json:"spendCents30d"`
	Tokens30d      int64        `json:"tokens30d"`
	CreditsCents   int64        `json:"creditsCents"`
	LastSync       string       `json:"lastSync"`
	Sources        []sourceStat `json:"sources"`
}

type orgAgg struct {
	Org          string `json:"org"`
	Display      string `json:"display"`
	Users        int    `json:"users"`
	Products     int    `json:"products"`
	SpendCents   int64  `json:"spendCents"`
	CreditsCents int64  `json:"creditsCents"`
	Tokens       int64  `json:"tokens"`
	Created      string `json:"created"`
}

type userOut struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	DisplayName   string `json:"displayName"`
	IsAdmin       bool   `json:"isAdmin"`
	IsGlobalAdmin bool   `json:"isGlobalAdmin"`
	Tag           string `json:"tag"`
	Created       string `json:"created"`
	LastSignin    string `json:"lastSignin"`
	Forbidden     bool   `json:"forbidden"`
}

type usagePoint struct {
	Date       string `json:"date"`
	SpendCents int64  `json:"spendCents"`
	Tokens     int64  `json:"tokens"`
	Requests   int64  `json:"requests"`
}

type usageByProduct struct {
	Product    string `json:"product"`
	SpendCents int64  `json:"spendCents"`
	Tokens     int64  `json:"tokens"`
}

type usageData struct {
	Totals    usagePoint       `json:"totals"`
	Series    []usagePoint     `json:"series"`
	ByProduct []usageByProduct `json:"byProduct"`
}

type productOut struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Org         string `json:"org"`
	Cluster     string `json:"cluster"`
	DeclaredTag string `json:"declaredTag"`
	RunningTag  string `json:"runningTag"`
	Health      string `json:"health"`
	Drift       bool   `json:"drift"`
	Updated     string `json:"updated"`
}

const iso = time.RFC3339

func scanCount(ctx context.Context, s *store, query string, args ...any) (int, error) {
	var n uint64
	row := s.conn.QueryRow(ctx, query, args...)
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return int(n), row.Err()
}

func (s *store) overview(ctx context.Context) (overviewData, error) {
	var o overviewData
	var err error
	if o.Orgs, err = scanCount(ctx, s, "SELECT count() FROM admin.dim_orgs"); err != nil {
		return o, err
	}
	o.Users, _ = scanCount(ctx, s, "SELECT count() FROM admin.dim_users")
	o.Products, _ = scanCount(ctx, s, "SELECT count() FROM admin.dim_products")
	o.ActiveProducts, _ = scanCount(ctx, s, "SELECT count() FROM admin.dim_products WHERE health='green'")
	o.Drift, _ = scanCount(ctx, s, "SELECT count() FROM admin.dim_products WHERE drift=1")

	o.SpendCents30d = sumWindow(ctx, s, "spend_cents", 30)
	o.Tokens30d = sumWindow(ctx, s, "tokens", 30)

	// Credits is a balance: take the latest snapshot day.
	if r := s.conn.QueryRow(ctx,
		`SELECT toInt64(round(sum(value))) FROM admin.fact_usage
		 WHERE metric='credits_cents' AND day=(SELECT max(day) FROM admin.fact_usage WHERE metric='credits_cents')`); r != nil {
		_ = r.Scan(&o.CreditsCents)
	}

	o.Sources, o.LastSync = s.sourceStats(ctx)
	return o, nil
}

func sumWindow(ctx context.Context, s *store, metric string, days int) int64 {
	var v float64
	from := time.Now().AddDate(0, 0, -days)
	r := s.conn.QueryRow(ctx,
		"SELECT sum(value) FROM admin.fact_usage WHERE metric=? AND day>=?", metric, from)
	if r != nil {
		_ = r.Scan(&v)
	}
	return int64(v + 0.5)
}

func (s *store) sourceStats(ctx context.Context) ([]sourceStat, string) {
	rows, err := s.conn.Query(ctx,
		"SELECT source, ok, rows, error, ts FROM admin.sync_runs ORDER BY ts DESC LIMIT 200")
	if err != nil {
		return nil, ""
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []sourceStat
	var last time.Time
	for rows.Next() {
		var src, errMsg string
		var ok uint8
		var n uint32
		var ts time.Time
		if err := rows.Scan(&src, &ok, &n, &errMsg, &ts); err != nil {
			continue
		}
		if ts.After(last) {
			last = ts
		}
		if seen[src] {
			continue
		}
		seen[src] = true
		out = append(out, sourceStat{Name: src, OK: ok == 1, Rows: int(n), Error: errMsg, At: ts.Format(iso)})
	}
	ls := ""
	if !last.IsZero() {
		ls = last.Format(iso)
	}
	return out, ls
}

func (s *store) listOrgs(ctx context.Context) ([]orgAgg, error) {
	usersBy := s.groupCount(ctx, "SELECT org, count() FROM admin.dim_users GROUP BY org")
	prodsBy := s.groupCount(ctx, "SELECT org, count() FROM admin.dim_products WHERE org!='' GROUP BY org")
	spendBy := s.groupSum(ctx, "SELECT org, sum(value) FROM admin.fact_usage WHERE metric='spend_cents' AND day>=? GROUP BY org", time.Now().AddDate(0, 0, -30))
	tokBy := s.groupSum(ctx, "SELECT org, sum(value) FROM admin.fact_usage WHERE metric='tokens' AND day>=? GROUP BY org", time.Now().AddDate(0, 0, -30))
	credBy := s.groupSum(ctx, "SELECT org, sum(value) FROM admin.fact_usage WHERE metric='credits_cents' AND day=(SELECT max(day) FROM admin.fact_usage WHERE metric='credits_cents') GROUP BY org")

	rows, err := s.conn.Query(ctx, "SELECT org, display, created FROM admin.dim_orgs ORDER BY org")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []orgAgg
	for rows.Next() {
		var org, display string
		var created time.Time
		if err := rows.Scan(&org, &display, &created); err != nil {
			continue
		}
		out = append(out, orgAgg{
			Org: org, Display: display,
			Users: usersBy[org], Products: prodsBy[org],
			SpendCents: int64(spendBy[org] + 0.5), Tokens: int64(tokBy[org] + 0.5),
			CreditsCents: int64(credBy[org] + 0.5),
			Created:      created.Format(iso),
		})
	}
	return out, rows.Err()
}

func (s *store) groupCount(ctx context.Context, query string, args ...any) map[string]int {
	m := map[string]int{}
	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v uint64
		if rows.Scan(&k, &v) == nil {
			m[k] = int(v)
		}
	}
	return m
}

func (s *store) groupSum(ctx context.Context, query string, args ...any) map[string]float64 {
	m := map[string]float64{}
	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v float64
		if rows.Scan(&k, &v) == nil {
			m[k] = v
		}
	}
	return m
}

func (s *store) listUsers(ctx context.Context, q, org string, limit, offset int) ([]userOut, int, error) {
	where := "WHERE (?='' OR org=?) AND (?='' OR positionCaseInsensitive(name,?)>0 OR positionCaseInsensitive(email,?)>0 OR positionCaseInsensitive(display,?)>0)"
	args := []any{org, org, q, q, q, q}
	total, _ := scanCount(ctx, s, "SELECT count() FROM admin.dim_users "+where, args...)

	rows, err := s.conn.Query(ctx,
		"SELECT org, name, email, display, is_admin, is_global_admin, tag, forbidden, created, last_signin FROM admin.dim_users "+
			where+" ORDER BY org, name LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []userOut
	for rows.Next() {
		var u userOut
		var isAdmin, isGA, forbidden uint8
		var created, lastSignin time.Time
		if err := rows.Scan(&u.Owner, &u.Name, &u.Email, &u.DisplayName, &isAdmin, &isGA, &u.Tag, &forbidden, &created, &lastSignin); err != nil {
			continue
		}
		u.IsAdmin, u.IsGlobalAdmin, u.Forbidden = isAdmin == 1, isGA == 1, forbidden == 1
		u.Created = created.Format(iso)
		if !lastSignin.IsZero() {
			u.LastSignin = lastSignin.Format(iso)
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *store) usage(ctx context.Context, org string, from, to time.Time) (usageData, error) {
	var d usageData
	rows, err := s.conn.Query(ctx,
		`SELECT day,
			toInt64(round(sumIf(value, metric='spend_cents'))),
			toInt64(round(sumIf(value, metric='tokens'))),
			toInt64(round(sumIf(value, metric='requests')))
		 FROM admin.fact_usage
		 WHERE day>=? AND day<=? AND (?='' OR org=?)
		 GROUP BY day ORDER BY day`, from, to, org, org)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var p usagePoint
		var day time.Time
		if err := rows.Scan(&day, &p.SpendCents, &p.Tokens, &p.Requests); err != nil {
			continue
		}
		p.Date = day.Format("2006-01-02")
		d.Series = append(d.Series, p)
		d.Totals.SpendCents += p.SpendCents
		d.Totals.Tokens += p.Tokens
		d.Totals.Requests += p.Requests
	}
	d.Totals.Date = "total"

	pr, err := s.conn.Query(ctx,
		`SELECT product,
			toInt64(round(sumIf(value, metric='spend_cents'))),
			toInt64(round(sumIf(value, metric='tokens')))
		 FROM admin.fact_usage
		 WHERE day>=? AND day<=? AND (?='' OR org=?)
		 GROUP BY product ORDER BY product`, from, to, org, org)
	if err == nil {
		defer pr.Close()
		for pr.Next() {
			var bp usageByProduct
			if pr.Scan(&bp.Product, &bp.SpendCents, &bp.Tokens) == nil {
				d.ByProduct = append(d.ByProduct, bp)
			}
		}
	}
	return d, nil
}

func (s *store) listProducts(ctx context.Context, kind string) ([]productOut, error) {
	rows, err := s.conn.Query(ctx,
		`SELECT name, kind, org, cluster, declared_tag, running_tag, health, drift, updated
		 FROM admin.dim_products WHERE (?='' OR kind=?) ORDER BY kind, org, name LIMIT 1000`, kind, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []productOut
	for rows.Next() {
		var p productOut
		var drift uint8
		var updated time.Time
		if err := rows.Scan(&p.Name, &p.Kind, &p.Org, &p.Cluster, &p.DeclaredTag, &p.RunningTag, &p.Health, &drift, &updated); err != nil {
			continue
		}
		p.Drift = drift == 1
		if !updated.IsZero() {
			p.Updated = updated.Format(iso)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
