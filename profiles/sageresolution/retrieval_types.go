package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

// Zero supplies the actual typed zero DIDURL to the relying party, bypassing
// no host or transport. It distinguishes invalid native input from adapter
// parser refusal. Options are passed to actual document dereferencing.
type RetrievalRequest struct {
	Reference string         `json:"reference"`
	Zero      bool           `json:"zero"`
	Purpose   string         `json:"purpose"`
	Options   map[string]any `json:"options,omitempty"`
}
type RetrievalCall struct {
	Input   string `json:"input"`
	Options []byte `json:"options"`
	Result  Result `json:"result"`
}
type RetrievalResult struct {
	Clock             int64           `json:"clock"`
	Operation         string          `json:"operation"`
	Reference         string          `json:"reference"`
	Purpose           string          `json:"purpose"`
	Calls             []RetrievalCall `json:"calls"`
	Method            []byte          `json:"method"`
	Error             string          `json:"error,omitempty"`
	Problem           []byte          `json:"problem"`
	ProblemSerializer string          `json:"problem_serializer,omitempty"`
	CaptureError      string          `json:"capture_error,omitempty"`
}
type RetrievalSubject interface {
	core.Subject
	InspectRetrieval(context.Context, sageprojection.Record, RetrievalRequest) (RetrievalResult, error)
}
