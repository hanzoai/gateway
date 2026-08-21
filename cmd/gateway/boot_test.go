// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

	run := exec.Command(bin, "run", "-c", path)
	var out bytes.Buffer
	run.Stdout, run.Stderr = &out, &out
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}

	bound, err := watch(port, wait(run))
	if err == nil {
		t.Fatalf("binary started on a config that classifies no route\n%s", out.String())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("run: %v", err)
	}
	if exit.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1 (a container restarts on non-zero and the rollout stalls)", exit.ExitCode())
	}
	if bound {
		t.Errorf("port %d accepted a connection; a TCP readiness probe would call this Ready", port)
	}
	t.Logf("exit=%d, never bound %d\n%s", exit.ExitCode(), port, out.String())
}

// The same binary, the same 63 routes, all of them classified: it binds, so the
// check is refusing a statement and not refusing to run.
func TestBootBindsWithAPolicy(t *testing.T) {
	bin := build(t)
	port := free(t)

	cfg := load(t, filepath.Join("..", "..", "tests", "fixtures", "policy", "unstated.json"))
	cfg["port"] = port
	for i, e := range cfg["endpoints"].([]any) {
		ep := e.(map[string]any)
		extra, _ := ep["extra_config"].(map[string]any)
		if extra == nil {
			extra = map[string]any{}
			ep["extra_config"] = extra
		}
		extra["auth/public"] = i == 0
	}
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

// watch reports whether anything ever accepted a connection on port before the
// process ended, and returns how it ended.
//
// The polling is the point. Asking once, after the process is gone, asks about
// a socket that is closed either way — it answers "nothing is listening" for a
// binary that bound the port, served, and then exited, which is exactly the
// failure the caller means to rule out.
func watch(port int, done <-chan error) (bool, error) {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	var bound bool
	for {
		select {
		case err := <-done:
			return bound || listening(port), err
		case <-tick.C:
			if listening(port) {
				bound = true
			}
		}
	}
}

// wait runs the process to completion on its own goroutine, so the caller can
// watch the port while it is alive.
func wait(run *exec.Cmd) <-chan error {
	done := make(chan error, 1)
	go func() { done <- run.Wait() }()
	return done
}

// A transient bind is what the watcher exists to catch: a process that takes
// the port, holds it briefly and then fails still passed its readiness probe.
func TestWatchCatchesATransientBind(t *testing.T) {
	port := free(t)
	done := make(chan error, 1)

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		listener.Close()
		time.Sleep(200 * time.Millisecond)
		done <- errors.New("exited")
	}()

	bound, err := watch(port, done)
	if err == nil {
		t.Fatal("watch reported success for a process that failed")
	}
	if !bound {
		t.Error("watch missed a port that was bound and released before the process ended")
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
