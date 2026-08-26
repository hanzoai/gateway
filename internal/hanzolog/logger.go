// Copyright © 2026 Hanzo AI. MIT License.

// Package hanzolog backs the engine's logging.Logger with luxfi/log, the one
// logging library every Hanzo Go service uses.
//
// It used to name a fork of that library instead (hanzoai/log), so this binary
// linked BOTH: the fork here, luxfi/log everywhere else in the module. Two
// logging libraries in one process is two answers to what a log line looks
// like, and the fork was a stale copy of the other — same package, same API,
// missing the wire that carries a line off the box.
//
// It replaces three vendored upstream components that each shipped their own
// logging stack — gologging (op/go-logging backend), logstash (a JSON pattern
// over gologging) and gelf (a Graylog UDP/TCP sink). Structured JSON with
// levels and timestamps is what luxfi/log emits natively, which is precisely
// what logstash's pattern existed to fake, so collapsing the three into one
// adapter loses no capability we use and drops two third-party dependencies
// (op/go-logging, Graylog2/go-gelf) from the edge binary.
//
// The extra_config namespace is UNCHANGED. `telemetry/logging` aliases onto
// the same canonical key the replaced component registered under, so every
// shipped gateway.json keeps working byte-for-byte — renaming it would leave
// the block silently unread and drop the configured level.
package hanzolog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	hlog "github.com/luxfi/log"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
)

// Namespace is the extra_config key holding the logging block. It keeps the
// canonical upstream spelling on purpose: it is a CONFIG-SURFACE key, not an
// import path, and `telemetry/logging` is aliased onto it in the engine's
// alias table. Rename it and every deployed config silently loses its logging
// settings.
const Namespace = "github_com/devopsfaith/krakend-gologging"

// ErrWrongConfig is returned when the service config carries no usable block
// under Namespace. Callers treat it as "not configured" and fall back.
var ErrWrongConfig = errors.New("getting the extra config for the telemetry/logging module")

// Config mirrors the keys the replaced component accepted, so a config written
// for it is read identically here.
type Config struct {
	Level  string
	StdOut bool
	Syslog bool
	Prefix string
	Format string
}

// levels maps the engine's log-level vocabulary onto luxfi/log's.
//
// This table is why the mapping is explicit rather than a pass-through to
// hlog.ParseLevel: that function does not know the words "WARNING" or
// "CRITICAL", and on an unknown level it falls back to INFO. A config asking
// for CRITICAL would therefore have been silently widened to INFO — quieter
// intent, noisier result, no error anywhere.
var levels = map[string]hlog.Level{
	"DEBUG":    hlog.DebugLevel,
	"INFO":     hlog.InfoLevel,
	"WARNING":  hlog.WarnLevel,
	"ERROR":    hlog.ErrorLevel,
	"CRITICAL": hlog.FatalLevel,
}

// ConfigGetter extracts the logging block, mirroring the key set of the
// component it replaces.
func ConfigGetter(e config.ExtraConfig) (Config, bool) {
	v, ok := e[Namespace]
	if !ok {
		return Config{}, false
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return Config{}, false
	}
	cfg := Config{}
	if v, ok := tmp["stdout"].(bool); ok {
		cfg.StdOut = v
	}
	if v, ok := tmp["syslog"].(bool); ok {
		cfg.Syslog = v
	}
	if v, ok := tmp["level"].(string); ok {
		cfg.Level = v
	}
	if v, ok := tmp["prefix"].(string); ok {
		cfg.Prefix = v
	}
	if v, ok := tmp["format"].(string); ok {
		cfg.Format = v
	}
	return cfg, true
}

// NewLogger returns a logging.Logger backed by luxfi/log.
//
// Unsupported settings are refused LOUDLY rather than ignored: a deployment
// that asks for syslog delivery or a custom text format and silently gets
// neither is worse than one that fails to boot and says why.
func NewLogger(cfg config.ExtraConfig, ws ...io.Writer) (logging.Logger, error) {
	c, ok := ConfigGetter(cfg)
	if !ok {
		return nil, ErrWrongConfig
	}
	if c.Syslog {
		return nil, errors.New(
			"telemetry/logging: syslog delivery is not supported; logs go to stdout " +
				"and are collected by the platform o11y stack")
	}
	switch strings.ToLower(c.Format) {
	case "", "default", "logstash", "json":
		// luxfi/log always emits structured JSON, which satisfies all of these.
	default:
		return nil, fmt.Errorf(
			"telemetry/logging: format %q is not supported; output is structured JSON", c.Format)
	}

	lvl, ok := levels[strings.ToUpper(strings.TrimSpace(c.Level))]
	if !ok {
		return nil, fmt.Errorf("telemetry/logging: unknown level %q", c.Level)
	}

	if c.StdOut {
		ws = append(ws, os.Stdout)
	}
	var w io.Writer
	switch len(ws) {
	case 0:
		w = io.Discard
	case 1:
		w = ws[0]
	default:
		w = io.MultiWriter(ws...)
	}

	l := hlog.NewWriter(w).With().Timestamp().Logger().Level(lvl)
	if c.Prefix != "" {
		// The prefix was a literal string glued onto every line by the old
		// text backend. As a field it stays greppable and becomes filterable.
		l = l.New("service", strings.Trim(c.Prefix, "[]"))
	}
	return Logger{l}, nil
}

// Logger adapts luxfi/log onto the engine's logging.Logger interface.
type Logger struct{ l hlog.Logger }

// msg joins variadic operands the way the engine's own logger does
// (fmt.Println semantics: single space between every pair), so call sites that
// read `logger.Error("[SERVICE: X]", err)` render unchanged.
func msg(v ...interface{}) string {
	return strings.TrimSuffix(fmt.Sprintln(v...), "\n")
}

// Debug implements logging.Logger.
func (g Logger) Debug(v ...interface{}) { g.l.Log(hlog.DebugLevel, msg(v...)) }

// Info implements logging.Logger.
func (g Logger) Info(v ...interface{}) { g.l.Log(hlog.InfoLevel, msg(v...)) }

// Warning implements logging.Logger.
func (g Logger) Warning(v ...interface{}) { g.l.Log(hlog.WarnLevel, msg(v...)) }

// Error implements logging.Logger.
func (g Logger) Error(v ...interface{}) { g.l.Log(hlog.ErrorLevel, msg(v...)) }

// Critical implements logging.Logger.
//
// It logs and RETURNS. The library's own Crit() delegates to Fatal(), which
// calls os.Exit(1) — but the engine's Critical is an ordinary severity that
// many components emit on recoverable errors, and only Fatal is defined to
// terminate. Routing Critical to Crit would kill the edge on the first
// critical line. Log() takes no exit hook, so it is the correct seam.
func (g Logger) Critical(v ...interface{}) { g.l.Log(hlog.FatalLevel, msg(v...)) }

// Fatal implements logging.Logger: it logs and then exits, per the interface.
func (g Logger) Fatal(v ...interface{}) { g.l.Fatal(msg(v...)) }

// Ensure interface compliance.
var _ logging.Logger = Logger{}
