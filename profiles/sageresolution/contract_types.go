package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

// ContractRequest selects a typed native entry. Zero sends the actual zero
// DID/DIDURL value; malformed textual input never counts as native rejection.
type ContractRequest struct {
	Request Request `json:"request"`
	Zero    bool    `json:"zero"`
}

// ContractResult records actual pre-call JSON input/options and unchanged
// output serializers. Reference is a separate same-record resolve call, not a
// trace of an internal resolver invocation and not an expected document.
type ContractResult struct {
	Operation         string         `json:"operation"`
	Identifier        []byte         `json:"identifier"`
	Options           []byte         `json:"options"`
	CaptureError      string         `json:"capture_error,omitempty"`
	Result            Result         `json:"result"`
	Metadata          MetadataResult `json:"metadata"`
	Reference         *Result        `json:"reference,omitempty"`
	Problem           []byte         `json:"problem,omitempty"`
	ProblemSerializer string         `json:"problem_serializer,omitempty"`
}
type ContractSubject interface {
	core.Subject
	InspectContract(context.Context, sageprojection.Record, ContractRequest) (ContractResult, error)
}
