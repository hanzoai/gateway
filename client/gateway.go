// Package client — canonical client interface for Hanzo Gateway.
//
//	import gw "github.com/hanzoai/gateway/client"
//	var g gw.Gateway = gateway.NewClient(cfg)

package client

import (
	"context"
	"io"
)

// Gateway is the LLM surface: complete, stream, embed, list, count.
// Streaming, tool-use, and structured-output are first class. Backend-
// specific knobs flow through Options.Extra without leaking into the
// signatures.
type Gateway interface {
	// Kind reports the backend identifier
	// (hanzo-gateway | litellm | openai-direct | anthropic-direct | ...).
	Kind() string

	// Complete runs a non-streaming chat completion.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResult, error)

	// Stream runs a streaming chat completion. The reader emits SSE JSON
	// chunks; closing it cancels the upstream request.
	Stream(ctx context.Context, req CompletionRequest) (io.ReadCloser, error)

	// Embed produces embedding vectors for a batch of inputs.
	Embed(ctx context.Context, req EmbedRequest) (*EmbedResult, error)

	// ListModels returns the model identifiers available on this backend.
	ListModels(ctx context.Context) ([]Model, error)

	// CountTokens returns the token count for text under the named model.
	CountTokens(ctx context.Context, model, text string) (int, error)
}

// CompletionRequest is the chat call shape.
type CompletionRequest struct {
	Model       string
	Messages    []Message
	MaxTokens   int
	Temperature float64
	Tools       []Tool
	// JSONMode requests parseable-JSON output; when ResponseSchema is
	// non-empty the backend validates against it.
	JSONMode       bool
	ResponseSchema map[string]any
	Stop           []string
	UserID         string
	OrgID          string
	// Extra is backend-specific (system_prompt_cache, seed, top_k, ...).
	Extra map[string]any
}

// Message is one turn. Role: system | user | assistant | tool.
type Message struct {
	Role       string
	Content    string
	Name       string
	ToolCallID string     // populated on role=tool
	ToolCalls  []ToolCall // populated on role=assistant
}

// Tool advertises a function the model may call.
type Tool struct {
	Name        string
	Description string
	// Parameters is a JSON Schema object describing the call signature.
	Parameters map[string]any
}

// ToolCall is the model's invocation request.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string // JSON string the caller parses
}

// CompletionResult is the non-streaming response.
type CompletionResult struct {
	Message      Message
	FinishReason string // stop | length | tool_calls | content_filter
	Usage        Usage
	// ModelUsed may differ from request when fallback or shadow routing
	// applies on the backend.
	ModelUsed string
}

// Delta is one chunk of a streaming response.
type Delta struct {
	Content      string
	ToolCallID   string
	ToolName     string
	ArgumentsAdd string
	FinishReason string
	Usage        Usage // populated on the final chunk
}

// Usage is the per-request accounting summary.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	PriceUSD         float64
}

// EmbedRequest is the embeddings call shape.
type EmbedRequest struct {
	Model  string
	Inputs []string
	UserID string
	OrgID  string
}

// EmbedResult is the embeddings response.
type EmbedResult struct {
	Vectors [][]float32
	Model   string
	Usage   Usage
}

// Model is the listing entry.
type Model struct {
	ID                    string
	Provider              string
	ContextSize           int
	Capabilities          []string // chat | embed | vision | tool_use | json | streaming
	PriceInUSDPerMillion  float64
	PriceOutUSDPerMillion float64
}
