package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// BaseContextResult captures the actual local library base-context API.
// It is not an HTTP retrieval observer or a full JSON-LD/RDF processor.
type BaseContextResult struct {
	Operation string `json:"operation"`
	Version   string `json:"version"`
	URL       string `json:"url"`
	Data      []byte `json:"data"`
	Error     string `json:"error,omitempty"`
}
type BaseContextSubject interface {
	core.Subject
	InspectBaseContext(context.Context) (BaseContextResult, error)
}
