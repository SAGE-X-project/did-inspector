// Package sageresolution observes SAGE record-backed resolution interfaces
// against pinned DID publications. It imports no subject implementation.
package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

// Request names a native operation or an inspector-built loopback TLS request.
// SourceFailure is an explicit fixture failure, never operational evidence.
type Request struct {
	Function      string            `json:"function"`
	Input         string            `json:"input"`
	Accept        string            `json:"accept,omitempty"`
	Relationship  string            `json:"relationship,omitempty"`
	SourceFailure string            `json:"source_failure,omitempty"`
	Options       map[string]any    `json:"options,omitempty"`
	HTTP          *core.HTTPRequest `json:"http,omitempty"`
}

// Result preserves native metadata and native bytes, or a complete wire exchange.
// ReturnedID and ContentKind translate typed native fields; they are not verdicts.
type Result struct {
	Metadata        json.RawMessage    `json:"metadata"`
	ContentMetadata json.RawMessage    `json:"content_metadata"`
	HasContent      bool               `json:"has_content"`
	ReturnedID      string             `json:"returned_id,omitempty"`
	ContentKind     string             `json:"content_kind,omitempty"`
	Snapshot        json.RawMessage    `json:"snapshot,omitempty"`
	Raw             []byte             `json:"raw,omitempty"`
	SageCode        string             `json:"sage_code,omitempty"`
	Exchange        *core.HTTPExchange `json:"exchange,omitempty"`
}

// Subject does not imply generic fixture-method or deployment capabilities.
type Subject interface {
	core.Subject
	InspectResolution(context.Context, sageprojection.Record, Request) (Result, error)
}
