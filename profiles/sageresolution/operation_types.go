package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

type LibraryOperationRequest struct {
	Kind   string `json:"kind"`
	Input  string `json:"input"`
	Refuse bool   `json:"refuse"`
}
type LibraryOperationResult struct {
	Request        LibraryOperationRequest `json:"request"`
	ParseOperation string                  `json:"parse_operation,omitempty"`
	Operation      string                  `json:"operation"`
	Wire           string                  `json:"wire"`
	Values         map[string]string       `json:"values"`
	VersionTime    string                  `json:"version_time"`
	Calls          int                     `json:"calls"`
	Results        []Result                `json:"results"`
	Error          string                  `json:"error,omitempty"`
}
type LibraryOperationSubject interface {
	core.Subject
	InspectLibraryOperation(context.Context, LibraryOperationRequest) (LibraryOperationResult, error)
}
