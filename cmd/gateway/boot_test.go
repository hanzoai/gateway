// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The readiness probe on this deployment is a TCP connect to the serving port.
// It reads no status and no body, so a process that has bound the port is
// Ready whatever it answers. That makes the ORDER of the credential-policy
// check the whole of it: the check has to run before the bind, or a config the
// binary refuses still passes readiness and the rollout completes.
//
// This test asserts the order the only way that cannot drift — it runs the
// shipping binary against a config that states no policy and connects to the
// port itself.
func TestBootBindsNothingWithoutAPolicy(t *testing.T) {
	bin := build(t)
	port := free(t)

	cfg := load(t, filepath.Join("..", "..", "tests", "fixtures", "policy", "unstated.json"))
	cfg["port"] = port
	path := write(t, cfg)

	out, err := exec.Command(bin, "run", "-c", path).CombinedOutput()
	if err == nil {
		t.Fatalf("binary started on a config that states no credential policy\n%s", out)
	}
	if code := err.(*exec.ExitError).ExitCode(); code != 1 {
		t.Errorf("exit code = %d, want 1 (a container restarts on non-zero and the rollout stalls)", code)
	}
	if listening(port) {
		t.Errorf("port %d accepted a connection; a TCP readiness probe would call this Ready", port)
	}
	t.Logf("exit=%d, nothing listening on %d\n%s", err.(*exec.ExitError).ExitCode(), port, out)
}

// The same binary, the same 63 routes, one of them classified: it binds, so
// the check is refusing a statement and not refusing to run.
func TestBootBindsWithAPolicy(t *testing.T) {
	bin := build(t)
	port := free(t)

	cfg := load(t, filepath.Join("..", "..", "tests", "fixtures", "policy", "unstated.json"))
	cfg["port"] = port
	first := cfg["endpoints"].([]any)[0].(map[string]any)
	first["extra_config"] = map[string]any{"auth/public": true}
	path := write(t, cfg)

	run := exec.Command(bin, "run", "-c", path)
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.Process.Kill() }()

	deadline := time.Now().Add(20 * time.Second)
	for !listening(port) {
		if time.Now().After(deadline) {
			t.Fatalf("port %d never accepted a connection", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// build compiles the binary that ships — the same tags the Dockerfile's
// `make build` uses, so this exercises the artifact and not a near-miss.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gateway")
	cmd := exec.Command("go", "build", "-tags", "legacy", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func free(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func load(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func write(t *testing.T, doc map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.json")
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
