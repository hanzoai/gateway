// Hanzo Ingress — lightweight host-based reverse proxy
// Replaces nginx-ingress with a minimal, config-driven proxy.
// TLS termination is handled by Cloudflare; this serves HTTP only.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type PathBackend struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

type HostRoute struct {
	Host     string        `json:"host"`
	Backends []PathBackend `json:"backends"`
}

type Config struct {
	Listen     string      `json:"listen"`
	Routes     []HostRoute `json:"routes"`
	HealthPath string      `json:"health_path"`
}

type router struct {
	mu     sync.RWMutex
	routes map[string][]backendEntry
}

type backendEntry struct {
	path  string
	proxy *httputil.ReverseProxy
}

func newRouter(cfg *Config) *router {
	r := &router{
		routes: make(map[string][]backendEntry),
	}

	for _, route := range cfg.Routes {
		var entries []backendEntry
		for _, b := range route.Backends {
			target, err := url.Parse(b.URL)
			if err != nil {
				log.Printf("WARN: invalid backend URL %q for %s: %v", b.URL, route.Host, err)
				continue
			}

			proxy := &httputil.ReverseProxy{
				Rewrite: func(pr *httputil.ProxyRequest) {
					pr.SetURL(target)
					pr.Out.Host = pr.In.Host
					// Forward all original headers
					for k, vv := range pr.In.Header {
						for _, v := range vv {
							pr.Out.Header.Add(k, v)
						}
					}
					pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
					pr.Out.Header.Set("X-Real-IP", clientIP(pr.In))
				},
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					MaxIdleConns:        200,
					MaxIdleConnsPerHost: 20,
					IdleConnTimeout:     90 * time.Second,
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					log.Printf("proxy error %s%s -> %s: %v", r.Host, r.URL.Path, target.String(), err)
					w.WriteHeader(http.StatusBadGateway)
					w.Write([]byte("502 Bad Gateway"))
				},
			}

			entries = append(entries, backendEntry{
				path:  b.Path,
				proxy: proxy,
			})
		}
		r.routes[route.Host] = entries
		log.Printf("  %s -> %d backends", route.Host, len(entries))
	}

	return r
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := strings.Split(req.Host, ":")[0]

	r.mu.RLock()
	entries, ok := r.routes[host]
	r.mu.RUnlock()

	if !ok {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	// Find longest matching path prefix
	var best *backendEntry
	bestLen := -1
	for i := range entries {
		p := entries[i].path
		if strings.HasPrefix(req.URL.Path, p) && len(p) > bestLen {
			best = &entries[i]
			bestLen = len(p)
		}
	}

	if best == nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	best.proxy.ServeHTTP(w, req)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func main() {
	configPath := flag.String("c", "/etc/ingress/ingress.json", "config file path")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/__health"
	}

	log.Printf("hanzo-ingress loading %d host routes", len(cfg.Routes))
	rt := newRouter(&cfg)

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", rt)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-sigs:
			log.Printf("signal received: %v, shutting down", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	go func() {
		log.Printf("hanzo-ingress listening on %s", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
	log.Println("hanzo-ingress stopped")
}
