package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// PolicyRequest reaches selected library actors with literal public documents.
// NonDocument is an explicit ordinary fixture return, never an operational
// Source result. Consume-only rejection is not relying-party policy evidence.
type PolicyRequest struct {
	Document    ConsumptionRequest `json:"document"`
	Mode        string             `json:"mode"`
	Reference   string             `json:"reference"`
	Purpose     string             `json:"purpose"`
	Now         string             `json:"now"`
	Options     map[string]any     `json:"options,omitempty"`
	NonDocument bool               `json:"non_document"`
}
type PolicyResult struct {
	Role         string             `json:"role"`
	Consumer     ConsumptionCapture `json:"consumer"`
	Methods      []ConsumedMethod   `json:"methods"`
	Retrieval    RetrievalResult    `json:"retrieval"`
	ClockValues  []string           `json:"clock_values"`
	CaptureError string             `json:"capture_error,omitempty"`
}
type PolicySubject interface {
	core.Subject
	InspectPolicy(context.Context, PolicyRequest) (PolicyResult, error)
}
