// Copyright © 2026 Hanzo AI. MIT License.

// zap_wire.go is the gateway-side ZAP wire contract per HIP-0110.
//
// Two envelopes cover the entire boundary between gateway and any
// backend (cloud, base, or future ZAP-speaking subsystem):
//
//   Forward — gateway → backend, one envelope per inbound HTTP request.
//             Carries the validated identity, the request method/path,
//             headers, body, and the gateway-assigned ConnID for any
//             future reverse-push correlation.
//
//   Push    — backend → gateway, one envelope per server-initiated push.
//             Carries the gateway-assigned ConnID and the pre-encoded
//             SSE / WebSocket frame the gateway writes verbatim to the
//             client socket. No JSON re-marshaling on the reverse path.
//
// On-wire bytes match github.com/luxfi/zap (the Go ZAP library) — see
// the `Object` / `Builder` API in that package. Field offsets follow
// the same layout policy as ~/work/hanzo/base/plugins/zap/handlers.go:
// fixed-size primitives packed at offset, Text/Bytes referenced by
// (int32 LE relative offset, uint32 LE length) at the field slot.
package gateway

import (
	"context"
	"sync"

	zaplib "github.com/luxfi/zap"
)

// ZAP message-type IDs reserved for the gateway↔backend boundary.
//
// These are upper-half (>= 0x1000) IDs to avoid colliding with the
// lower-half IDs used inside base for its own plugin protocol
// (MsgTypeCollections=100, MsgTypeRecords=101, MsgTypeAuth=102,
// MsgTypeRealtime=103 — see ~/work/hanzo/base/plugins/zap/handlers.go).
const (
	// MsgTypeForward is the gateway → backend request envelope.
	MsgTypeForward uint16 = 0x1010

	// MsgTypePush is the backend → gateway reverse-push envelope.
	MsgTypePush uint16 = 0x1020
)

// Forward envelope field offsets. Packed in declaration order. The
// fixed slot region is 96 bytes; variable-length fields (Text, Bytes)
// follow the slot region and are referenced from inside it by
// (int32 rel-offset, uint32 length) pairs.
//
// Layout:
//
//   slot[ 0..3]  IsAdmin        bool  (1 byte) + 3 pad
//   slot[ 4..11] Permissions    int64
//   slot[12..23] TenantID       Text  (int32 off + uint32 len + pad)
//   slot[24..35] UserID         Text
//   slot[36..47] Method         Text
//   slot[48..59] Path           Text
//   slot[60..71] ConnID         Text
//   slot[72..83] Headers        Bytes (canonicalized header map)
//   slot[84..95] Body           Bytes (raw client body)
const (
	fwdIsAdmin     = 0
	fwdPermissions = 4
	fwdTenantID    = 12
	fwdUserID      = 24
	fwdMethod      = 36
	fwdPath        = 48
	fwdConnID      = 60
	fwdHeaders     = 72
	fwdBody        = 84
	fwdSlotSize    = 96
)

// Push envelope field offsets. Smaller because reverse push only needs
// the ConnID and the pre-encoded frame bytes.
//
//   slot[ 0..11] ConnID    Text
//   slot[12..23] Frame     Bytes
//   slot[24..35] Encoding  Text  ("sse" | "ws-text" | "ws-binary")
const (
	pushConnID   = 0
	pushFrame    = 12
	pushEncoding = 24
	pushSlotSize = 36
)

// EncSSE / EncWSText / EncWSBinary are the canonical Encoding values
// the gateway recognizes on a Push envelope.
const (
	EncSSE      = "sse"
	EncWSText   = "ws-text"
	EncWSBinary = "ws-binary"
)

// BuildForward serializes a Forward envelope into a ZAP message. The
// caller hands the result to zaplib.Conn.Send (fire-and-forget) or
// zaplib.Node.Call (request-response).
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

// BuildPush serializes a Push envelope into a ZAP message.
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

// Forward is the typed view of a forward envelope. Constructed from
// the validated zip.Ctx at the gateway edge; consumed by cloud / base
// as the entire authenticated request.
type Forward struct {
	TenantID    string // X-Org-Id (JWT 'owner')
	UserID      string // X-User-Id (JWT 'sub')
	IsAdmin     bool   // X-User-IsAdmin (JWT 'isAdmin')
	Permissions int64  // X-User-Permissions (bit.Field)
	Method      string // GET, POST, ...
	Path        string // /v1/iam/users/123
	Headers     []byte // canonicalized header map (serialization owned by gateway)
	Body        []byte // raw client body, verbatim
	ConnID      string // gateway-assigned conn id; empty for one-shot REST
}

// Push is the typed view of a reverse-push envelope.
type Push struct {
	ConnID   string // identifies the gateway-held client connection
	Frame    []byte // pre-encoded SSE event or WebSocket frame payload
	Encoding string // "sse" | "ws-text" | "ws-binary"
}

// PushSink is implemented by anything that delivers a Push frame to a
// concrete client connection. The gateway's BuildApp installs the
// canonical implementation backed by an in-memory sync.Map keyed by
// ConnID.
type PushSink interface {
	Deliver(ctx context.Context, p Push) error
}

// pushRegistry is the gateway's in-process conn table. Goroutine-safe
// via sync.Map. Lookup is O(1). The registry is populated by realtime
// handlers in gateway.BuildApp at subscribe-time and consumed by
// HandleReversePush below.
var pushRegistry sync.Map // map[ConnID]PushSink

// RegisterReversePush is called by realtime handlers in gateway.BuildApp
// when a client opens an SSE / WS subscription. After registration, any
// Push envelope arriving on the ZAP socket with this ConnID will be
// delivered to sink.
func RegisterReversePush(connID string, sink PushSink) {
	pushRegistry.Store(connID, sink)
}

// UnregisterReversePush is called when the client connection closes.
// Subsequent Push envelopes targeting this ConnID are silently dropped.
func UnregisterReversePush(connID string) {
	pushRegistry.Delete(connID)
}

// HandleReversePush is the zaplib.Handler installed by cmd/gateway/main
// onto the ZAP node. It decodes the Push envelope, looks up the matching
// PushSink, and delegates delivery. Unknown ConnIDs (client gone) are a
// silent no-op — the originating backend has no way to know the client
// reconnected to a different gateway replica.
func HandleReversePush(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
	p := ReadPush(msg)
	v, ok := pushRegistry.Load(p.ConnID)
	if !ok {
		// Client gone — drop silently. Backend will time out its sub.
		return nil, nil
	}
	sink, ok := v.(PushSink)
	if !ok {
		return nil, nil
	}
	if err := sink.Deliver(ctx, p); err != nil {
		// Drop the registration on delivery failure; backend will see
		// the same silent-drop next time it pushes.
		pushRegistry.Delete(p.ConnID)
		return nil, err
	}
	return nil, nil
}
