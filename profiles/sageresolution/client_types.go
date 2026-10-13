package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

// ClientRequest invokes the actual library client, never checks.BindingRequest.
// Reply is a controlled server fixture for a client parsing contrast only.
type ClientRequest struct {
	Request Request `json:"request"`
	Post    bool    `json:"post"`
	Reply   []byte  `json:"reply,omitempty"`
}
type ClientWire struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	Accept       string `json:"accept"`
	ContentType  string `json:"content_type"`
	Body         []byte `json:"body"`
	CaptureError string `json:"capture_error,omitempty"`
}
type ClientResult struct {
	Operation   string               `json:"operation"`
	Request     ClientRequest        `json:"request"`
	Endpoint    string               `json:"endpoint"`
	Wire        []ClientWire         `json:"wire"`
	ServerCalls int                  `json:"server_calls"`
	ServerTLS   bool                 `json:"server_tls"`
	ServerRole  string               `json:"server_role"`
	Consumer    []ConsumptionCapture `json:"consumer"`
	Result      Result               `json:"result"`
}
type ClientSubject interface {
	core.Subject
	InspectClient(context.Context, sageprojection.Record, ClientRequest) (ClientResult, error)
}
