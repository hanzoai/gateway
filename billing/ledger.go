// Copyright © 2026 Hanzo AI. MIT License.

// Package billing is the gateway's metering substrate: the ONE place AI
// usage is authorized (balance pre-check) and accounted (usage decrement),
// so chat / console / cloud-api / any surface stop re-implementing billing.
//
// It is decomplected into orthogonal pieces, each independently complete and
// testable:
//
//   - Ledger  (this file): the one billing ledger — commerce — behind an
//     interface so the transport (HTTP now, ZAP later) is swappable and the
//     meter is testable against a mock.
//   - Pricer  (pricing.go): a pure function model+tokens → cents. Swappable.
//   - Meter   (meter.go):   composes Ledger + Pricer into two gin/proxy hooks
//     — a fail-closed authorization PRE-check and a fail-open accounting
//     POST-call decrement.
//   - Config  (config.go):  env wiring; default OFF, observe-before-enforce.
//
// Identity is never re-derived here. The edge (auth_middleware.go / gate.go,
// package iamauth) already validated the IAM JWT and minted the canonical
// X-Org-Id from the `owner` claim. The meter consumes that gateway-minted
// tenant — NON-forgeable (client-supplied X-Org-Id is stripped before any
// allow path) — and never trusts a request-supplied billing identity.
package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Cents is the gateway's view of a money amount, in integer USD cents — the
// same unit commerce stores (currency.Cents). One unit, no floats.
type Cents int64

// Balance is a tenant's spendable position as reported by commerce.
// Available = Balance - Holds, floored at 0. A tenant may proceed when
// Available > min (see Meter).
type Balance struct {
	User      string
	Currency  string
	Balance   Cents
	Holds     Cents
	Available Cents
}

// Usage is one metered AI call to be charged to a tenant's ledger. Tenant is
// the gateway-minted org slug (validated-JWT `owner`), never client-supplied.
type Usage struct {
	Tenant           string
	Model            string
	Provider         string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Stream           bool
	RequestID        string
	Amount           Cents // computed cost (see Pricer)
}

// Ledger is the ONE billing ledger the gateway meters against. Commerce is
// the sole implementation; the interface exists so (a) the transport is
// swappable — HTTP to commerce.hanzo.svc:8001 now, ZAP forward-RPC later —
// without touching policy, and (b) the meter is unit-testable against a mock.
type Ledger interface {
	// Balance reports the tenant's spendable position. tenant is the
	// gateway-minted (validated-JWT-derived) org slug; bearer is the user's
	// IAM token, forwarded for defense-in-depth so commerce can independently
	// re-validate. Identity is NON-forgeable: the IAM-native /me/balance
	// endpoint resolves the org from the trusted X-Org-Id header, never a
	// client-supplied ?user= param.
	Balance(ctx context.Context, tenant, bearer string) (Balance, error)

	// ReportUsage decrements the tenant's balance by u.Amount. This is the
	// accounting write: service-authenticated, because only the metering
	// authority (the gateway) may write a tenant's ledger — a user can never
	// write their own usage. u.Tenant is gateway-derived from the validated
	// JWT, so the SourceId is not client-forgeable.
	ReportUsage(ctx context.Context, u Usage) error
}

// CommerceLedger is the HTTP implementation of Ledger against hanzoai/commerce
// (commerce.hanzo.svc:8001). It speaks the proven, IAM-native contract:
//
//	GET  /v1/billing/me/balance?currency=usd   (X-Org-Id tenant; user JWT)
//	POST /v1/billing/usage                      (service token; X-Org-Id tenant)
//
// Both amounts are integer cents. The pre-check forwards the user's own JWT
// (non-forgeable identity); the decrement uses the gateway's service token
// (the ledger-write authority).
type CommerceLedger struct {
	baseURL      string
	serviceToken string
	balanceHTTP  *http.Client
	usageHTTP    *http.Client
}

// NewCommerceLedger builds a CommerceLedger. baseURL is the commerce origin
// (e.g. http://commerce.hanzo.svc.cluster.local:8001); serviceToken is the
// admin-scoped COMMERCE_SERVICE_TOKEN used only for the usage-write.
//
// Two clients with distinct timeouts: the balance pre-check is on the request
// critical path so it is tight (fail fast → fail closed); the usage decrement
// is off the critical path (fire-and-forget) so it tolerates more latency.
func NewCommerceLedger(baseURL, serviceToken string) *CommerceLedger {
	return &CommerceLedger{
		baseURL:      trimSlash(baseURL),
		serviceToken: serviceToken,
		balanceHTTP:  &http.Client{Timeout: 3 * time.Second},
		usageHTTP:    &http.Client{Timeout: 8 * time.Second},
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// meBalanceResponse mirrors commerce GetMyBalance (api/billing/me.go) — all
// fields are integer cents except the string identifiers.
type meBalanceResponse struct {
	User      string `json:"user"`
	Currency  string `json:"currency"`
	Balance   int64  `json:"balance"`
	Holds     int64  `json:"holds"`
	Available int64  `json:"available"`
}

// Balance implements Ledger via GET /v1/billing/me/balance. The tenant is
// carried in the gateway-minted X-Org-Id header (commerce's GetOrganization
// resolves the org from it); the user's bearer is forwarded so commerce can
// independently re-validate the JWT. No forgeable identity crosses the wire.
func (l *CommerceLedger) Balance(ctx context.Context, tenant, bearer string) (Balance, error) {
	if l.baseURL == "" {
		return Balance{}, fmt.Errorf("billing: no commerce URL configured")
	}
	u := l.baseURL + "/v1/billing/me/balance?currency=usd"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Balance{}, err
	}
	// X-Org-Id is the authoritative, non-forgeable tenant (gateway-minted from
	// the validated JWT owner claim). Commerce resolves the org from it.
	req.Header.Set("X-Org-Id", tenant)
	// Forward the user's IAM token (defense in depth): commerce may re-validate
	// the JWT and confirm the owner matches X-Org-Id.
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := l.balanceHTTP.Do(req)
	if err != nil {
		return Balance{}, fmt.Errorf("billing: balance unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return Balance{}, fmt.Errorf("billing: balance status %d: %s", resp.StatusCode, snippet(body))
	}
	var r meBalanceResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return Balance{}, fmt.Errorf("billing: balance decode: %w", err)
	}
	return Balance{
		User:      r.User,
		Currency:  r.Currency,
		Balance:   Cents(r.Balance),
		Holds:     Cents(r.Holds),
		Available: Cents(r.Available),
	}, nil
}

// usageRequest mirrors commerce RecordUsage (api/billing/usage.go) exactly —
// field names and json tags must stay in lockstep with that struct.
type usageRequest struct {
	User             string `json:"user"`
	Currency         string `json:"currency"`
	Amount           int64  `json:"amount"` // cents
	Model            string `json:"model"`
	Provider         string `json:"provider"`
	PromptTokens     int    `json:"promptTokens"`
	CompletionTokens int    `json:"completionTokens"`
	TotalTokens      int    `json:"totalTokens"`
	RequestID        string `json:"requestId"`
	Stream           bool   `json:"stream"`
	Status           string `json:"status"`
}

// ReportUsage implements Ledger via POST /v1/billing/usage. Service-
// authenticated (admin-scoped token); the tenant is sent both as the body
// `user` (the SourceId) and as X-Org-Id (the namespace) — commerce's
// destination-key == namespace-slug invariant requires they match.
func (l *CommerceLedger) ReportUsage(ctx context.Context, u Usage) error {
	if l.baseURL == "" {
		return fmt.Errorf("billing: no commerce URL configured")
	}
	if u.Amount <= 0 {
		return nil // commerce skips amount<=0; save the round-trip.
	}
	payload := usageRequest{
		User:             u.Tenant,
		Currency:         "usd",
		Amount:           int64(u.Amount),
		Model:            u.Model,
		Provider:         u.Provider,
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
		RequestID:        u.RequestID,
		Stream:           u.Stream,
		Status:           "completed",
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL+"/v1/billing/usage", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", u.Tenant)
	if l.serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+l.serviceToken)
	}
	resp, err := l.usageHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("billing: usage unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("billing: usage status %d: %s", resp.StatusCode, snippet(body))
	}
	return nil
}

// snippet bounds an error-body echo so logs never balloon.
func snippet(b []byte) string {
	const max = 256
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

// QueryEscapeTenant is exported only so callers building diagnostics reuse the
// same escaping the ledger uses internally (kept trivial + DRY).
func QueryEscapeTenant(t string) string { return url.QueryEscape(t) }

// FormatCents renders cents as a base-10 string (no float). Used in logs.
func FormatCents(c Cents) string { return strconv.FormatInt(int64(c), 10) }
