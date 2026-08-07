package cel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/plugin/cel/internal"
)

func ProxyFactory(l logging.Logger, pf proxy.Factory) proxy.Factory {
	return proxy.FactoryFunc(func(cfg *config.EndpointConfig) (proxy.Proxy, error) {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][CEL]"
		next, err := pf.New(cfg)
		if err != nil {
			return next, err
		}

		def, ok := internal.ConfigGetter(cfg.ExtraConfig)
		if !ok {
			return next, nil
		}
		l.Debug(logPrefix, "Loading configuration")

		p, err := newProxy(l, logPrefix, def, next)
		if err != nil {
			// An endpoint that DECLARES a check and cannot compile it is
			// refused, at boot, where the router is built.
			//
			// This used to warn and return `next` — the pipe without the
			// check. So a rule with a typo in it, or one naming a variable
			// this environment does not declare, produced an endpoint that
			// looked guarded in config, logged two lines at Warning nobody
			// reads, and then served everything. That is precisely how
			// info.peers stayed open on three public API hosts behind a rule
			// written to forbid it. Failing to start is loud, happens before
			// any traffic, and cannot be mistaken for a working gate.
			l.Error(logPrefix, "Refusing to serve an endpoint whose check cannot be compiled:", err.Error())
			return nil, fmt.Errorf("%s cel: %w", logPrefix, err)
		}
		return p, nil
	})
}

func BackendFactory(l logging.Logger, bf proxy.BackendFactory) proxy.BackendFactory {
	return func(cfg *config.Backend) proxy.Proxy {
		logPrefix := "[BACKEND: " + cfg.URLPattern + "][CEL]"
		next := bf(cfg)

		def, ok := internal.ConfigGetter(cfg.ExtraConfig)
		if !ok {
			return next
		}
		l.Debug(logPrefix, "Loading configuration")

		p, err := newProxy(l, logPrefix, def, next)
		if err != nil {
			l.Warning(logPrefix, "Error parsing the definitions:", err.Error())
			l.Warning(logPrefix, "Falling back to the next backend proxy")
			return next
		}
		return p
	}
}

func newProxy(l logging.Logger, name string, defs []internal.InterpretableDefinition, next proxy.Proxy) (proxy.Proxy, error) {
	p := internal.NewCheckExpressionParser(l)
	preEvaluators, err := p.ParsePre(defs)
	if err != nil {
		return proxy.NoopProxy, err
	}
	postEvaluators, err := p.ParsePost(defs)
	if err != nil {
		return proxy.NoopProxy, err
	}

	l.Debug(name, fmt.Sprintf("%d preEvaluator(s) loaded", len(preEvaluators)))
	l.Debug(name, fmt.Sprintf("%d postEvaluator(s) loaded", len(postEvaluators)))

	return func(ctx context.Context, r *proxy.Request) (*proxy.Response, error) {
		now := timeNow().Format("2006-01-02T15:04:05.999Z07:00")

		body, err := readBodyForEval(r, len(preEvaluators) > 0)
		if err != nil {
			l.Warning(name, "Rejecting: request body not readable for evaluation:", err.Error())
			return nil, err
		}

		if err := evalChecks(l, name+"[pre]", newReqActivation(r, body, now), preEvaluators); err != nil {
			return nil, err
		}

		resp, err := next(ctx, r)
		if err != nil {
			l.Debug(name, "Delegated execution failed:", err.Error())
			return resp, err
		}

		if err := evalChecks(l, name+"[post]", newRespActivation(resp, now), postEvaluators); err != nil {
			return nil, err
		}

		return resp, nil
	}, nil
}

func evalChecks(l logging.Logger, name string, args map[string]interface{}, ps []cel.Program) error {
	for i, eval := range ps {
		res, _, err := eval.Eval(args)
		if err != nil {
			l.Info(fmt.Sprintf("%s Evaluator #%d failed: %v", name, i, res))
			return fmt.Errorf("request aborted by evaluator #%d", i)
		}

		resultMsg := fmt.Sprintf("%s Evaluator #%d result: %v", name, i, res)

		if v, ok := res.Value().(bool); !ok || !v {
			l.Info(resultMsg)
			return fmt.Errorf("request aborted by evaluator #%d", i)
		}
		l.Debug(resultMsg)
	}
	return nil
}

// MaxEvaluatedBodyBytes bounds what a pre-evaluator is shown of the request.
//
// The body has to be held in memory to be both matched and replayed to the
// backend, so an unbounded read is a memory amplifier an unauthenticated
// caller controls.
const MaxEvaluatedBodyBytes = 1 << 20 // 1 MiB

// ErrBodyTooLarge is returned when the request body exceeds
// MaxEvaluatedBodyBytes, so a guarded endpoint REFUSES it.
//
// Truncating instead would be the dangerous choice: the filter would match
// against a prefix and pass whatever sat past the cut, which turns the cap
// itself into the bypass — pad ahead of the method name and the rule stops
// seeing it. A body the guard cannot read in full is a body the guard cannot
// clear.
var ErrBodyTooLarge = errors.New("cel: request body exceeds the evaluable limit")

// readBodyForEval returns the request body as a string and puts it back on the
// Request so the backend still receives it. Reading is skipped entirely when
// no pre-evaluator will look at it, which keeps the cost on the endpoints that
// actually declare a rule.
func readBodyForEval(r *proxy.Request, wanted bool) (string, error) {
	if !wanted || r == nil || r.Body == nil {
		return "", nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, MaxEvaluatedBodyBytes+1))
	r.Body.Close()
	if err != nil {
		return "", err
	}
	if len(buf) > MaxEvaluatedBodyBytes {
		return "", ErrBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return string(buf), nil
}

func newReqActivation(r *proxy.Request, body, now string) map[string]interface{} {
	return map[string]interface{}{
		internal.PreKey + "_method":      r.Method,
		internal.PreKey + "_path":        r.Path,
		internal.PreKey + "_params":      r.Params,
		internal.PreKey + "_headers":     r.Headers,
		internal.PreKey + "_querystring": r.Query,
		internal.PreKey + "_body":        body,
		internal.NowKey:                  now,
	}
}

func newRespActivation(r *proxy.Response, now string) map[string]interface{} {
	return map[string]interface{}{
		internal.PostKey + "_completed":        r.IsComplete,
		internal.PostKey + "_metadata_status":  r.Metadata.StatusCode,
		internal.PostKey + "_metadata_headers": r.Metadata.Headers,
		internal.PostKey + "_data":             r.Data,
		internal.NowKey:                        now,
	}
}

var timeNow = time.Now
