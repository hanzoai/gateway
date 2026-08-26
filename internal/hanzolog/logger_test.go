package hanzolog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
)

func extra(m map[string]interface{}) config.ExtraConfig {
	return config.ExtraConfig{Namespace: m}
}

// ONE LOGGING LIBRARY. This adapter named a fork of luxfi/log while the rest of
// the module named luxfi/log itself, so the edge binary linked both — two
// answers to what a log line looks like, and only one of them has a wire off
// the box. The test is what keeps the answer at one: a line the engine emits
// must be the structured JSON every other Hanzo service writes, with the level
// and the message where a reader looks for them.
func TestALineIsTheStructuredJsonTheEstateReads(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(extra(map[string]interface{}{"level": "INFO", "prefix": "[EDGE]"}), &buf)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Error("[SERVICE: X]", "upstream refused")

	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("output %q is not structured JSON: %v", buf.String(), err)
	}
	if line["level"] != "error" {
		t.Errorf("level = %v, want error", line["level"])
	}
	if got, _ := line["message"].(string); got != "[SERVICE: X] upstream refused" {
		t.Errorf("message = %q, want the operands joined the way the engine joins them", got)
	}
	if line["service"] != "EDGE" {
		t.Errorf("service = %v, want the prefix as a field a reader can filter on", line["service"])
	}
	if _, stamped := line["time"]; !stamped {
		t.Error("no timestamp — every other line in the estate carries one")
	}
}

// The configured level is a floor, not decoration: a deployment that asks for
// ERROR and still gets INFO is paying for volume it asked not to have.
func TestTheConfiguredLevelIsAFloor(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(extra(map[string]interface{}{"level": "ERROR"}), &buf)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Info("routine")
	if buf.Len() != 0 {
		t.Errorf("an INFO line was written under an ERROR floor: %s", buf.String())
	}
	l.Error("broken")
	if !strings.Contains(buf.String(), "broken") {
		t.Errorf("the ERROR line did not reach the writer: %q", buf.String())
	}
}

// CRITICAL must not take the edge down. The library's own Crit() delegates to
// Fatal() and exits; the engine emits Critical on recoverable errors, so the
// adapter routes it to a plain log at fatal severity. A test process that
// survives this call IS the assertion.
func TestCriticalLogsAndReturns(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(extra(map[string]interface{}{"level": "DEBUG"}), &buf)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	l.Critical("the pool is exhausted")
	if !strings.Contains(buf.String(), "the pool is exhausted") {
		t.Fatalf("nothing written: %q", buf.String())
	}
}

// Settings this backend cannot honour are refused rather than dropped: a
// deployment that asked for syslog and silently got stdout has a delivery it
// believes in and does not have.
func TestUnsupportedSettingsAreRefused(t *testing.T) {
	for name, cfg := range map[string]map[string]interface{}{
		"syslog":        {"level": "INFO", "syslog": true},
		"text format":   {"level": "INFO", "format": "custom"},
		"unknown level": {"level": "LOUD"},
	} {
		if _, err := NewLogger(extra(cfg)); err == nil {
			t.Errorf("%s was accepted; a setting that cannot be honoured must say so", name)
		}
	}
	if _, err := NewLogger(config.ExtraConfig{}); err != ErrWrongConfig {
		t.Errorf("an absent block = %v, want ErrWrongConfig", err)
	}
}
