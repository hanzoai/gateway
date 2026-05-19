// Copyright © 2026 Hanzo AI. MIT License.

// zap_wire.go is the gateway-side ZAP wire contract per HIP-0110.
//
// Two envelopes cover the entire gateway↔backend boundary:
//   Forward — gateway → backend, one envelope per inbound HTTP request.
//   Push    — backend → gateway, one envelope per server-initiated push.
// On-wire bytes match github.com/luxfi/zap. Field offsets follow the
// same packing as base/plugins/zap.
package gateway

import (
	"context"
	"sync"

	zaplib "github.com/luxfi/zap"
)

// HIP-0110 message-type IDs. zap.FinishWithFlags expects the type in the
// upper byte of a uint16 (`type << 8`), so types must fit in uint8.
// Picked in the 0x80+ range so they don't collide with base/plugins/zap's
// lower-byte IDs (Collections=100, Records=101, Auth=102, Realtime=103).
const (
	MsgTypeForward   uint16 = 0x80
	MsgTypePush      uint16 = 0x81
	MsgTypeSubscribe uint16 = 0x82
)

const (
	fwdIsAdmin, fwdPermissions          = 0, 4
	fwdTenantID, fwdUserID              = 12, 24
	fwdMethod, fwdPath                  = 36, 48
	fwdConnID                           = 60
	fwdHeaders, fwdBody                 = 72, 84
	fwdSlotSize                         = 96
	pushConnID, pushFrame, pushEncoding = 0, 12, 24
	pushSlotSize                        = 36
)

// Canonical Encoding values on a Push envelope.
const (
	EncSSE      = "sse"
	EncWSText   = "ws-text"
	EncWSBinary = "ws-binary"
)

// Forward is the typed view of the gateway→backend envelope.
type Forward struct {
	TenantID    string // X-Org-Id (JWT 'owner')
	UserID      string // X-User-Id (JWT 'sub')
	IsAdmin     bool   // X-User-IsAdmin (JWT 'isAdmin')
	Permissions int64  // X-User-Permissions (bit.Field)
	Method      string // GET, POST, ...
	Path        string // /v1/iam/users/123
	Headers     []byte // canonicalized header map
	Body        []byte // raw client body, verbatim
	ConnID      string // gateway-assigned conn id for reverse push
}

// Push is the typed view of the backend→gateway reverse-push envelope.
type Push struct {
	ConnID   string
	Frame    []byte // pre-encoded SSE / WebSocket payload
	Encoding string // "sse" | "ws-text" | "ws-binary"
}

// BuildForward serializes f into a ZAP message.
func BuildForward(f Forward) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(256 + len(f.Headers) + len(f.Body))
	ob := b.StartObject(fwdSlotSize)
	ob.SetBool(fwdIsAdmin, f.IsAdmin)
	ob.SetInt64(fwdPermissions, f.Permissions)
	ob.SetText(fwdTenantID, f.TenantID)
	ob.SetText(fwdUserID, f.UserID)
	ob.SetText(fwdMethod, f.Method)
	ob.SetText(fwdPath, f.Path)
	ob.SetText(fwdConnID, f.ConnID)
	ob.SetBytes(fwdHeaders, f.Headers)
	ob.SetBytes(fwdBody, f.Body)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgTypeForward << 8))
}

// ReadForward decodes a Forward envelope from a parsed message.
func ReadForward(msg *zaplib.Message) Forward {
	r := msg.Root()
	return Forward{
		TenantID:    r.Text(fwdTenantID),
		UserID:      r.Text(fwdUserID),
		IsAdmin:     r.Bool(fwdIsAdmin),
		Permissions: r.Int64(fwdPermissions),
		Method:      r.Text(fwdMethod),
		Path:        r.Text(fwdPath),
		Headers:     r.Bytes(fwdHeaders),
		Body:        r.Bytes(fwdBody),
		ConnID:      r.Text(fwdConnID),
	}
}

// BuildPush serializes p into a ZAP message.
func BuildPush(p Push) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(64 + len(p.Frame))
	ob := b.StartObject(pushSlotSize)
	ob.SetText(pushConnID, p.ConnID)
	ob.SetBytes(pushFrame, p.Frame)
	ob.SetText(pushEncoding, p.Encoding)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgTypePush << 8))
}

// ReadPush decodes a Push envelope.
func ReadPush(msg *zaplib.Message) Push {
	r := msg.Root()
	return Push{
		ConnID:   r.Text(pushConnID),
		Frame:    r.Bytes(pushFrame),
		Encoding: r.Text(pushEncoding),
	}
}

// PushSink delivers a Push frame to a client connection. gateway.BuildApp
// registers the canonical impl backed by an in-memory map keyed by ConnID.
type PushSink interface {
	Deliver(ctx context.Context, p Push) error
}

var pushRegistry sync.Map // ConnID → PushSink

// RegisterReversePush records the sink for an active SSE / WS subscription.
func RegisterReversePush(connID string, sink PushSink) { pushRegistry.Store(connID, sink) }

// UnregisterReversePush is called when the client conn closes.
func UnregisterReversePush(connID string) { pushRegistry.Delete(connID) }

// HandleReversePush is the zaplib.Handler installed by cmd/gateway/main.
// Decodes the Push envelope, looks up the matching sink, delivers. Unknown
// ConnID (client gone) is a silent no-op.
func HandleReversePush(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
	p := ReadPush(msg)
	v, ok := pushRegistry.Load(p.ConnID)
	if !ok {
		return nil, nil
	}
	sink, ok := v.(PushSink)
	if !ok {
		return nil, nil
	}
	if err := sink.Deliver(ctx, p); err != nil {
		pushRegistry.Delete(p.ConnID)
		return nil, err
	}
	return nil, nil
}
