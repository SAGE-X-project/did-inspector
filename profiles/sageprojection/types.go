// Package sageprojection inspects produced SAGE documents against pinned
// DID publication statements. It imports no subject implementation.
package sageprojection

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// Record is public, explicitly untrusted fixture data, not registry evidence.
type Record struct {
	DID     string `json:"did"`
	State   string `json:"state"`
	Version string `json:"version"`
	Keys    []Key  `json:"keys"`
}

// Key is public fixture material; no private keys are used.
type Key struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	MaterialHex string `json:"material_hex"`
	State       string `json:"state"`
	Expires     *int64 `json:"expires,omitempty"`
}

// Result preserves the actual projection bytes and diagnostic.
type Result struct {
	Raw         []byte `json:"raw"`
	MediaType   string `json:"media_type"`
	ProblemCode string `json:"problem_code"`
}

// Subject is a narrow projection operation, not a generic DID producer,
// validator, resolver or protected-message verifier. Cases assert this
// extension directly rather than declaring unrelated core capabilities.
type Subject interface {
	core.Subject
	Project(context.Context, Record, string) (Result, error)
}
