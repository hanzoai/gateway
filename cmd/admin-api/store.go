package main

import (
	"context"
	"fmt"
	"time"

	datastore "github.com/hanzo-ds/go"
	"github.com/hanzo-ds/go/lib/driver"
)

// store is the admin analytics layer: a thin typed surface over the dedicated
// `admin` database in the ZAP-native Hanzo Datastore. All names are fully
// qualified (`admin.*`) so the connection itself binds to `default` and the
// `admin` db is created on bootstrap.
type store struct {
	conn driver.Conn
	db   string
}

func openStore(cfg *config) (*store, error) {
	conn, err := datastore.Open(&datastore.Options{
		Addr:     []string{cfg.dsAddr},
		Protocol: datastore.Native,
		Auth: datastore.Auth{
			Database: "default",
			Username: cfg.dsUser,
			Password: cfg.dsPassword,
		},
		DialTimeout: 10 * time.Second,
		Settings:    datastore.Settings{"final": 1},
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &store{conn: conn, db: cfg.dsDatabase}, nil
}

func (s *store) Close() { _ = s.conn.Close() }

// bootstrap creates the `admin` database and tables idempotently. Kept in sync
// with hanzoai/datastore/hanzo/admin-schema.sql (the canonical reference).
func (s *store) bootstrap(ctx context.Context) error {
	stmts := []string{
		`CREATE DATABASE IF NOT EXISTS admin`,
		`CREATE TABLE IF NOT EXISTS admin.dim_orgs (
			org String, display String, source LowCardinality(String) DEFAULT 'iam',
			created DateTime64(3), synced_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (org)`,
		`CREATE TABLE IF NOT EXISTS admin.dim_users (
			org String, name String, email String, display String,
			is_admin UInt8 DEFAULT 0, is_global_admin UInt8 DEFAULT 0,
			tag String DEFAULT '', forbidden UInt8 DEFAULT 0,
			created DateTime64(3), last_signin DateTime64(3),
			synced_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (org, name)`,
		`CREATE TABLE IF NOT EXISTS admin.dim_products (
			name String, kind LowCardinality(String), org String DEFAULT '',
			cluster String DEFAULT '', declared_tag String DEFAULT '', running_tag String DEFAULT '',
			health LowCardinality(String) DEFAULT 'unknown', drift UInt8 DEFAULT 0,
			updated DateTime64(3), synced_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (kind, org, name)`,
		`CREATE TABLE IF NOT EXISTS admin.fact_usage (
			day Date, org String, product LowCardinality(String), metric LowCardinality(String),
			value Float64, currency LowCardinality(String) DEFAULT 'usd',
			synced_at DateTime64(3) DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(synced_at)
		  PARTITION BY toYYYYMM(day) ORDER BY (org, product, metric, day)`,
		`CREATE TABLE IF NOT EXISTS admin.sync_runs (
			ts DateTime64(3) DEFAULT now64(3), source LowCardinality(String),
			ok UInt8, rows UInt32 DEFAULT 0, error String DEFAULT ''
		) ENGINE = MergeTree ORDER BY (ts)`,
	}
	for _, q := range stmts {
		if err := s.conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("ddl %.40q: %w", q, err)
		}
	}
	return nil
}

// ---- writes (batch upserts into ReplacingMergeTree) -----------------------

type orgRow struct {
	Org, Display, Source string
	Created              time.Time
}

func (s *store) upsertOrgs(ctx context.Context, rows []orgRow) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO admin.dim_orgs (org, display, source, created)")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := b.Append(r.Org, r.Display, nz(r.Source, "iam"), r.Created); err != nil {
			return err
		}
	}
	return b.Send()
}

type userRow struct {
	Org, Name, Email, Display, Tag    string
	IsAdmin, IsGlobalAdmin, Forbidden uint8
	Created, LastSignin               time.Time
}

func (s *store) upsertUsers(ctx context.Context, rows []userRow) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO admin.dim_users (org, name, email, display, is_admin, is_global_admin, tag, forbidden, created, last_signin)")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := b.Append(r.Org, r.Name, r.Email, r.Display, r.IsAdmin, r.IsGlobalAdmin, r.Tag, r.Forbidden, r.Created, r.LastSignin); err != nil {
			return err
		}
	}
	return b.Send()
}

type productRow struct {
	Name, Kind, Org, Cluster, DeclaredTag, RunningTag, Health string
	Drift                                                     uint8
	Updated                                                   time.Time
}

func (s *store) upsertProducts(ctx context.Context, rows []productRow) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO admin.dim_products (name, kind, org, cluster, declared_tag, running_tag, health, drift, updated)")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := b.Append(r.Name, r.Kind, r.Org, r.Cluster, r.DeclaredTag, r.RunningTag, nz(r.Health, "unknown"), r.Drift, r.Updated); err != nil {
			return err
		}
	}
	return b.Send()
}

type usageRow struct {
	Day      time.Time
	Org      string
	Product  string
	Metric   string
	Value    float64
	Currency string
}

func (s *store) upsertUsage(ctx context.Context, rows []usageRow) error {
	if len(rows) == 0 {
		return nil
	}
	b, err := s.conn.PrepareBatch(ctx, "INSERT INTO admin.fact_usage (day, org, product, metric, value, currency)")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := b.Append(r.Day, r.Org, r.Product, r.Metric, r.Value, nz(r.Currency, "usd")); err != nil {
			return err
		}
	}
	return b.Send()
}

func (s *store) recordSync(ctx context.Context, source string, ok bool, n int, errMsg string) {
	var okv uint8
	if ok {
		okv = 1
	}
	_ = s.conn.Exec(ctx,
		"INSERT INTO admin.sync_runs (source, ok, rows, error) VALUES (?, ?, ?, ?)",
		source, okv, uint32(n), errMsg)
}

func nz(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
