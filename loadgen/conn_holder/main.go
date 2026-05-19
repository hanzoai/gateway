// Package main holds N idle keep-alive HTTP/1.1 connections against a
// target URL. Used to measure the gateway's per-connection memory cost.
//
//	go run ./loadgen/conn_holder -target=http://localhost:8080/healthz \
//	  -conns=10000 -hold=120s
//
// Each goroutine establishes one TCP connection, issues a single GET,
// then keeps the connection idle until -hold elapses. The Transport is
// per-goroutine to prevent connection reuse — every -conns count is a
// distinct on-the-wire socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	var (
		target    = flag.String("target", "http://localhost:8080/healthz", "URL to GET on each connection")
		conns     = flag.Int("conns", 10000, "number of concurrent connections to hold")
		hold      = flag.Duration("hold", 120*time.Second, "how long to hold the connections idle after the first request")
		dialTime  = flag.Duration("dial-timeout", 10*time.Second, "per-conn dial timeout")
		reportInt = flag.Duration("report-interval", 5*time.Second, "stats reporting interval")
	)
	flag.Parse()

	if *conns <= 0 {
		fmt.Fprintln(os.Stderr, "conns must be > 0")
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("signal received — draining")
		cancel()
	}()

	var (
		established atomic.Int64
		failed      atomic.Int64
		held        atomic.Int64
	)

	go func() {
		t := time.NewTicker(*reportInt)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("established=%d failed=%d holding=%d",
					established.Load(), failed.Load(), held.Load())
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(*conns)
	for i := 0; i < *conns; i++ {
		go func() {
			defer wg.Done()
			if err := holdOne(ctx, *target, *dialTime, *hold, &established, &held); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	log.Printf("done — established=%d failed=%d", established.Load(), failed.Load())
}

func holdOne(ctx context.Context, target string, dialTimeout, hold time.Duration, established, held *atomic.Int64) error {
	// Per-goroutine Transport with explicit Dialer and no MaxIdleConnsPerHost.
	// Keepalive on for the hold window so the conn stays open.
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext:        dialer.DialContext,
		DisableCompression: true,
		DisableKeepAlives:  false,
		MaxIdleConns:       1,
		IdleConnTimeout:    hold + 10*time.Second,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 0}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	established.Add(1)
	held.Add(1)
	defer held.Add(-1)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(hold):
		return nil
	}
}
