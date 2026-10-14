package sageresolution

import (
	"context"
	"github.com/sage-x-project/did-inspector/core"
)

type RoutingBindingResult struct {
	Request      RoutingRequest     `json:"request"`
	Method       string             `json:"method"`
	Role         string             `json:"role"`
	Native       []ClientInvocation `json:"native"`
	Exchange     core.HTTPExchange  `json:"exchange"`
	CaptureError string             `json:"capture_error,omitempty"`
}
type RoutingBindingSubject interface {
	core.Subject
	InspectRoutingBinding(context.Context, RoutingRequest, string) (RoutingBindingResult, error)
}
