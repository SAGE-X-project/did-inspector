package sage

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func urlParts(u did.DIDURL) sageresolution.URLParts {
	return sageresolution.URLParts{Input: u.String(), Primary: u.WithoutFragment().String(), Fragment: u.Fragment(), HasFragment: u.HasFragment(), Path: u.Path(), Query: u.Query(), HasQuery: u.HasQuery()}
}

// This explicitly selected extension-point observer always declines handling.
// It records the actual URL/document/options and does not produce a resource,
// alter the supplied values or use the eventual NOT_FOUND as a URL oracle.
func observeResourceHandler(out *sageresolution.RoutingResult) dereferencer.ResourceHandler {
	return func(_ context.Context, u did.DIDURL, res resolution.Result, opts resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
		c := sageresolution.ResourceHandlerCapture{Operation: "github.com/sage-x-project/did-go/dereferencer.ResourceHandler", Role: "literal passive resource handler; records actual values and returns unhandled", URL: urlParts(u)}
		var err error
		c.Options, err = json.Marshal(opts)
		if err != nil {
			c.CaptureError = joinRoutingCapture(c.CaptureError, err.Error())
		}
		c.Metadata, err = json.Marshal(res.ResolutionMetadata)
		if err != nil {
			c.CaptureError = joinRoutingCapture(c.CaptureError, err.Error())
		}
		if res.Document != nil {
			var capture string
			c.Model, c.Entries, capture = captureMaps(res.Document)
			c.CaptureError = joinRoutingCapture(c.CaptureError, capture)
		}
		out.CaptureError = joinRoutingCapture(out.CaptureError, c.CaptureError)
		out.ResourceHandler = append(out.ResourceHandler, c)
		return resolution.DereferenceResult{}, false
	}
}
