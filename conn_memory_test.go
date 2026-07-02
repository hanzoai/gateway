// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// Per-connection memory profile for the gateway edge. Measures
// heap-alloc growth while N concurrent HTTP/1.1 clients hold long
// requests open — this isolates fasthttp's goroutine-per-conn cost
// from per-request work. Run with:
//
//	go test -mod=mod -run=TestConnMemory -v -conn-count=10000

package gateway

import (
	"context"
	"flag"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"
)

var connCount = flag.Int("conn-count", 1000, "concurrent connections to hold")

func TestConnMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory profile in -short mode")
	}
	n := *connCount

	// Bring up a minimal zip.App that hangs on /hold until the test
	// closes the context.
	app := zip.New(zip.Config{
		Logger:                luxlog.New("test", "conn-memory"),
		DisableStartupMessage: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var holding atomic.Int64
	app.Get("/hold", func(c *zip.Ctx) error {
		holding.Add(1)
		defer holding.Add(-1)
		// Block until shutdown. Fiber returns when the underlying
		// fasthttp.RequestCtx is closed; cancelling ctx triggers shutdown.
		<-ctx.Done()
		return nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = app.Fiber().Listener(ln) }()
	defer func() { _ = app.Shutdown() }()

	// Settle baseline.
	time.Sleep(200 * time.Millisecond)
	var baseline, peak runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&baseline)

	// Raw TCP dial — no http.Client (which would spawn 3 goroutines
	// per request, contaminating the gateway-side memory profile).
	// We send a minimal HTTP/1.1 request and then sit on the conn.
	req := []byte("GET /hold HTTP/1.1\r\nHost: x\r\n\r\n")
	conns := make([]net.Conn, 0, n)
	var connsMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			if _, err := c.Write(req); err != nil {
				_ = c.Close()
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
		}()
	}
	wg.Wait()
	defer func() {
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
	}()

	// Wait for all conns to be accepted.
	deadline := time.Now().Add(30 * time.Second)
	for holding.Load() < int64(n) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := holding.Load(); got < int64(n) {
		t.Logf("only %d/%d conns accepted before deadline", got, n)
		n = int(got)
	}

	runtime.GC()
	runtime.ReadMemStats(&peak)

	delta := int64(peak.HeapAlloc) - int64(baseline.HeapAlloc)
	perConn := float64(delta) / float64(n)
	totalGoroutines := runtime.NumGoroutine()

	fmt.Printf("\n=== Per-connection memory profile ===\n")
	fmt.Printf("conns held       : %d\n", n)
	fmt.Printf("baseline heap    : %s\n", humanBytes(int64(baseline.HeapAlloc)))
	fmt.Printf("peak heap        : %s\n", humanBytes(int64(peak.HeapAlloc)))
	fmt.Printf("delta            : %s\n", humanBytes(delta))
	fmt.Printf("per-conn heap    : %.0f B (%.2f KiB)\n", perConn, perConn/1024)
	fmt.Printf("goroutines total : %d\n", totalGoroutines)
	fmt.Printf("goroutines / conn: %.2f\n", float64(totalGoroutines)/float64(n))
	fmt.Printf("=====================================\n\n")

	cancel()
	wg.Wait()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < 0 {
		return "-" + humanBytes(-n)
	}
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
