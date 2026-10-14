package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

type TrustResult struct {
	Role              string `json:"role"`
	Endpoint          string `json:"endpoint"`
	ClientResult      Result `json:"client_result"`
	HTTPCalls         int    `json:"http_calls"`
	ClientVerified    bool   `json:"client_verified"`
	ServerVerified    bool   `json:"server_verified"`
	TLSVersion        uint16 `json:"tls_version"`
	ClientCertificate []byte `json:"client_certificate"`
	ServerCertificate []byte `json:"server_certificate"`
	ClientPeer        []byte `json:"client_peer"`
	ServerPeer        []byte `json:"server_peer"`
	ClientMissing     bool   `json:"client_missing"`
	CaptureError      string `json:"capture_error,omitempty"`
}
type TrustSubject interface {
	core.Subject
	InspectTrust(context.Context, sageprojection.Record, bool) (TrustResult, error)
}
