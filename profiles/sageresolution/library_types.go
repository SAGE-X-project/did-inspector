package sageresolution

import "context"
import "github.com/sage-x-project/did-inspector/core"

// SyntaxRequest selects a pinned library parser, not SAGE method ingress.
type SyntaxRequest struct {
	Kind  string `json:"kind"`
	Input string `json:"input"`
	Base  string `json:"base,omitempty"`
}
type SyntaxResult struct {
	Operation string        `json:"operation"`
	Request   SyntaxRequest `json:"request"`
	Value     string        `json:"value"`
	Error     string        `json:"error,omitempty"`
}
type SyntaxSubject interface {
	core.Subject
	InspectSyntax(context.Context, SyntaxRequest) (SyntaxResult, error)
}

// CodecRequest supplies public deterministic test vectors for encoding only.
type CodecRequest struct {
	Name    string `json:"name"`
	Secret  bool   `json:"secret"`
	Key     []byte `json:"key"`
	Encoded string `json:"encoded"`
}
type CodecResult struct {
	Operation    string       `json:"operation"`
	Request      CodecRequest `json:"request"`
	Name         string       `json:"name"`
	Prefix       []byte       `json:"prefix"`
	Length       int          `json:"length"`
	Secret       bool         `json:"secret"`
	Encoded      string       `json:"encoded"`
	EncodeError  string       `json:"encode_error,omitempty"`
	Decoded      []byte       `json:"decoded"`
	DecodeName   string       `json:"decode_name"`
	DecodePrefix []byte       `json:"decode_prefix"`
	DecodeLength int          `json:"decode_length"`
	DecodeSecret bool         `json:"decode_secret"`
	DecodeError  string       `json:"decode_error,omitempty"`
}
type CodecSubject interface {
	core.Subject
	InspectCodec(context.Context, CodecRequest) (CodecResult, error)
}
