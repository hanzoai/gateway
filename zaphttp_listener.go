//go:build legacy
// +build legacy

// ZAP-HTTP listener — serves the same fully-wrapped handler chain as the
// HTTP listener, but over the github.com/zap-proto/http binary protocol.
//
// This is purely additive: the existing HTTP path on the lura RunServer
// stays unchanged. The ZAP-HTTP listener boots in a goroutine alongside
// it. Boot failures are warned, never fatal — gateway must keep serving
// HTTP even if ZAP boot fails.
//
// Knobs (env):
//
//	KRAKEND_ZAP_LISTEN — bind addr for the ZAP-HTTP listener.
//	                     Default ":9999". Set to "off" or "" to disable.
//
// Wire-up: see DefaultRunServerFactory.NewRunServer in executor.go,
// which calls startZapHTTPListenerOnce with the final composed handler
// before delegating to the lura RunServer.

package gateway

import (
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	zaphttp "github.com/zap-proto/http"

	"github.com/luraproject/lura/v2/logging"
)

const (
	// envZapHTTPListen is the env var that sets the ZAP-HTTP bind address.
	// Empty string or "off" disables the listener entirely.
	envZapHTTPListen = "KRAKEND_ZAP_LISTEN"

	// defaultZapHTTPAddr is the bind address used when the env var is unset.
	defaultZapHTTPAddr = ":9999"
)

// zapHTTPState tracks the once-only listener boot.
type zapHTTPState struct {
	once    sync.Once
	booted  atomic.Bool
	server  atomic.Pointer[zaphttp.Server]
	bootErr atomic.Pointer[error]
}

// defaultZapHTTPState is the package-level state for the listener. It's
// gated by sync.Once so multiple RunServer invocations (e.g. async-agent
// restarts) only ever spawn one ZAP-HTTP listener.
var defaultZapHTTPState zapHTTPState

// startZapHTTPListenerOnce spawns a ZAP-HTTP listener serving the given
// handler in a goroutine. Subsequent calls are no-ops — the first handler
// wins. ZAP-HTTP boot errors are logged at Warning and never returned;
// the HTTP path must keep serving.
func startZapHTTPListenerOnce(logger logging.Logger, handler http.Handler) {
	defaultZapHTTPState.once.Do(func() {
		addr := zapHTTPListenAddr()
		if addr == "" {
			logger.Info("[SERVICE: ZAP-HTTP] Listener disabled (KRAKEND_ZAP_LISTEN=off)")
			return
		}
		// Wrap the handler so every ZAP-HTTP request logs a single
		// line with method, path, and status. This is the on-the-wire
		// proof that traffic arrived as a ZAP frame (not as a plain
		// HTTP/1.1 socket fallback): only zap-proto/http-encoded
		// frames make it through `zaphttp.Server` decoding.
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &zapStatusRecorder{ResponseWriter: w, status: http.StatusOK}
			handler.ServeHTTP(rec, r)
			logger.Info("[ZAP-WIRE]", r.Method, r.URL.Path, rec.status)
		})
		srv := &zaphttp.Server{Addr: addr, Handler: wrapped}
		defaultZapHTTPState.server.Store(srv)
		go func() {
			logger.Info("[SERVICE: ZAP-HTTP] Listening on", addr)
			defaultZapHTTPState.booted.Store(true)
			if err := srv.ListenAndServe(); err != nil {
				logger.Warning("[SERVICE: ZAP-HTTP] Listener exited:", err.Error())
				defaultZapHTTPState.bootErr.Store(&err)
			}
		}()
	})
}

// zapHTTPListenAddr returns the configured bind address, or the empty
// string if the listener should be disabled. "off" (case-insensitive)
// is the documented kill switch.
func zapHTTPListenAddr() string {
	v, ok := os.LookupEnv(envZapHTTPListen)
	if !ok {
		return defaultZapHTTPAddr
	}
	switch v {
	case "", "off", "OFF", "Off", "false", "0":
		return ""
	default:
		return v
	}
}

// stopZapHTTPListener closes the ZAP-HTTP listener if it was started.
// Called from tests and from the executor on shutdown.
func stopZapHTTPListener() {
	if srv := defaultZapHTTPState.server.Load(); srv != nil {
		_ = srv.Close()
	}
}

// resetZapHTTPListenerForTest clears the once-guard so tests can spawn
// a fresh listener. Test-only.
func resetZapHTTPListenerForTest() {
	stopZapHTTPListener()
	defaultZapHTTPState = zapHTTPState{}
}

// zapStatusRecorder captures the HTTP status the handler wrote so the
// `[ZAP-WIRE]` log line can include it. We don't buffer the body —
// zap-proto/http already buffers internally, so this is just a status
// observer.
type zapStatusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (z *zapStatusRecorder) WriteHeader(code int) {
	if !z.wrote {
		z.status = code
		z.wrote = true
	}
	z.ResponseWriter.WriteHeader(code)
}

func (z *zapStatusRecorder) Write(b []byte) (int, error) {
	if !z.wrote {
		z.status = http.StatusOK
		z.wrote = true
	}
	return z.ResponseWriter.Write(b)
}
