package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// RoutingRequest configures the root library selected by SAGE with a literal
// example driver. It is not a SAGE registry or a historical/authoritative method.
type RoutingRequest struct {
	Document ConsumptionRequest `json:"document"`
	Request  Request            `json:"request"`
}
type RoutingResult struct {
	Consumption       []ConsumptionCapture `json:"consumption,omitempty"`
	Role              string               `json:"role"`
	Request           RoutingRequest       `json:"request"`
	Operation         string               `json:"operation"`
	Options           []byte               `json:"options"`
	ResolveInputs     []string             `json:"resolve_inputs"`
	ResolveOptions    [][]byte             `json:"resolve_options"`
	DriverInputs      []string             `json:"driver_inputs"`
	DriverResults     [][]byte             `json:"driver_results"`
	DriverOptions     [][]byte             `json:"driver_options"`
	DataModel         []byte               `json:"data_model"`
	Entries           []byte               `json:"entries"`
	Result            Result               `json:"result"`
	CaptureError      string               `json:"capture_error,omitempty"`
	ResolvedDataModel []byte               `json:"resolved_data_model,omitempty"`
	ResolvedEntries   []byte               `json:"resolved_entries,omitempty"`
	ResolvedMetadata  []byte               `json:"resolved_metadata,omitempty"`
}
type RoutingSubject interface {
	core.Subject
	InspectRouting(context.Context, RoutingRequest) (RoutingResult, error)
}
