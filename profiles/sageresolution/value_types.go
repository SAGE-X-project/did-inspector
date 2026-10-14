package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// LibraryValueRequest exercises a typed library reader/validator/serializer.
// It supplies no registry history, method-issued equivalence or valid proofs.
type LibraryValueRequest struct {
	Kind    string `json:"kind"`
	Input   []byte `json:"input"`
	Subject string `json:"subject"`
}
type LibraryValueResult struct {
	Request         LibraryValueRequest `json:"request"`
	Reader          string              `json:"reader"`
	Validator       string              `json:"validator"`
	Writer          string              `json:"writer"`
	ReadError       string              `json:"read_error,omitempty"`
	ValidationError string              `json:"validation_error,omitempty"`
	WriteError      string              `json:"write_error,omitempty"`
	Output          []byte              `json:"output"`
}
type LibraryValueSubject interface {
	core.Subject
	InspectLibraryValue(context.Context, LibraryValueRequest) (LibraryValueResult, error)
}
