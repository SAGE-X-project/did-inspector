package sage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func applicationHandlerOptions(q sageresolution.RoutingRequest, out *sageresolution.RoutingResult) ([]dereferencer.Option, error) {
	if q.ApplicationHandler == "" {
		return nil, nil
	}
	if (q.ApplicationHandler != "handled" && q.ApplicationHandler != "unhandled") || q.Request.Function != "dereference" || q.PlainJSONFragment || q.ObserveProduction || q.ObserveResourceHandler {
		return nil, errors.New("requires explicit isolated application handler observation")
	}
	return []dereferencer.Option{dereferencer.WithResourceHandler(applicationResourceHandler(q.ApplicationHandler, out))}, nil
}

func applicationResourceHandler(mode string, out *sageresolution.RoutingResult) dereferencer.ResourceHandler {
	return func(_ context.Context, u did.DIDURL, res resolution.Result, opts resolution.DereferenceOptions) (resolution.DereferenceResult, bool) {
		c := sageresolution.ApplicationResourceCapture{Input: sageresolution.ResourceHandlerCapture{Operation: "github.com/sage-x-project/did-go/dereferencer.ResourceHandler", Role: "explicit controlled application callback; not SAGE method support", URL: urlParts(u)}, Handled: mode == "handled"}
		var err error
		c.Input.Options, err = json.Marshal(opts)
		if err != nil {
			c.Input.CaptureError = err.Error()
		}
		c.Input.Metadata, err = json.Marshal(res.ResolutionMetadata)
		if err != nil {
			c.Input.CaptureError = joinRoutingCapture(c.Input.CaptureError, err.Error())
		}
		if res.Document != nil {
			var e string
			c.Input.Model, c.Input.Entries, e = captureMaps(res.Document)
			c.Input.CaptureError = joinRoutingCapture(c.Input.CaptureError, e)
		}
		result := resolution.DereferenceResult{}
		if c.Handled {
			resource, _ := document.NewMap(document.Entry{Key: "id", Value: document.String("did:example:resources/public-resource")}, document.Entry{Key: "label", Value: document.String("public application resource")})
			result = resolution.DereferenceResult{ContentStream: resource, DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "application/json"}, ContentMetadata: document.Metadata{VersionID: "application-1"}}
		}
		c.Returned, err = dereferenceResult(sageresolution.Result{}, result.DereferencingMetadata, result.ContentStream, result.ContentMetadata)
		if err != nil {
			c.Input.CaptureError = joinRoutingCapture(c.Input.CaptureError, err.Error())
		}
		out.CaptureError = joinRoutingCapture(out.CaptureError, c.Input.CaptureError)
		out.ApplicationHandler = append(out.ApplicationHandler, c)
		return result, c.Handled
	}
}
