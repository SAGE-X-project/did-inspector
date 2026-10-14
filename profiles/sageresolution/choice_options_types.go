package sageresolution

import "context"
import "github.com/sage-x-project/did-inspector/core"

// ConsumptionOptionsRequest selects additional options at the direct library
// boundary. It is not a SAGE resolver ingress or an authority assertion.
type ConsumptionOptionsRequest struct {
	Document ConsumptionRequest `json:"document"`
	Require  string             `json:"require"`
	Strict   bool               `json:"strict"`
}
type ConsumptionOptionsSubject interface {
	core.Subject
	InspectConsumptionOptions(context.Context, ConsumptionOptionsRequest) (ConsumptionCapture, error)
}
