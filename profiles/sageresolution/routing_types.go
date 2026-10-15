package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

// RoutingRequest configures the root library selected by SAGE with a literal
// example driver. It is not a SAGE registry or a historical/authoritative method.
type RoutingRequest struct {
	PlainJSONFragment      bool               `json:"plain_json_fragment,omitempty"`
	ObserveProduction      bool               `json:"observe_production,omitempty"`
	ObserveResourceHandler bool               `json:"observe_resource_handler,omitempty"`
	Document               ConsumptionRequest `json:"document"`
	Request                Request            `json:"request"`
}

// URLParts snapshots the actual subject URL value without changing it.
type URLParts struct {
	Input       string `json:"input"`
	Primary     string `json:"primary"`
	Fragment    string `json:"fragment"`
	HasFragment bool   `json:"has_fragment"`
	Path        string `json:"path"`
	Query       string `json:"query"`
	HasQuery    bool   `json:"has_query"`
}
type ResourceHandlerCapture struct {
	Operation    string   `json:"operation"`
	Role         string   `json:"role"`
	URL          URLParts `json:"url"`
	Options      []byte   `json:"options"`
	Model        []byte   `json:"model"`
	Entries      []byte   `json:"entries"`
	Metadata     []byte   `json:"metadata"`
	CaptureError string   `json:"capture_error,omitempty"`
}
type RoutingResult struct {
	Production        []ProductionCapture      `json:"production,omitempty"`
	ResourceHandler   []ResourceHandlerCapture `json:"resource_handler,omitempty"`
	Consumption       []ConsumptionCapture     `json:"consumption,omitempty"`
	Role              string                   `json:"role"`
	Request           RoutingRequest           `json:"request"`
	Operation         string                   `json:"operation"`
	Options           []byte                   `json:"options"`
	ResolveInputs     []string                 `json:"resolve_inputs"`
	ResolveOptions    [][]byte                 `json:"resolve_options"`
	DriverInputs      []string                 `json:"driver_inputs"`
	DriverResults     [][]byte                 `json:"driver_results"`
	DriverOptions     [][]byte                 `json:"driver_options"`
	DataModel         []byte                   `json:"data_model"`
	Entries           []byte                   `json:"entries"`
	Result            Result                   `json:"result"`
	CaptureError      string                   `json:"capture_error,omitempty"`
	ResolvedDataModel []byte                   `json:"resolved_data_model,omitempty"`
	ResolvedEntries   []byte                   `json:"resolved_entries,omitempty"`
	ResolvedMetadata  []byte                   `json:"resolved_metadata,omitempty"`
}
type RoutingSubject interface {
	core.Subject
	InspectRouting(context.Context, RoutingRequest) (RoutingResult, error)
}
