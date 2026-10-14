package sage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

type literalRoutingMethod struct {
	body    []byte
	calls   *[][]byte
	inputs  *[]string
	results *[][]byte
}

func (literalRoutingMethod) Name() string       { return "example" }
func (literalRoutingMethod) Produces() []string { return []string{"application/did"} }
func (literalRoutingMethod) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, method.ErrNotSupported
}
func (literalRoutingMethod) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, method.ErrNotSupported
}
func (literalRoutingMethod) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, method.ErrNotSupported
}
func (m literalRoutingMethod) Read(_ context.Context, id did.DID, o method.ReadOptions) (*method.ReadResult, error) {
	b, e := json.Marshal(o)
	if e != nil {
		return nil, e
	}
	*m.calls = append(*m.calls, b)
	result := &method.ReadResult{Data: append([]byte(nil), m.body...), ContentType: "application/did"}
	if m.inputs != nil {
		*m.inputs = append(*m.inputs, id.String())
	}
	if m.results != nil {
		b, e := json.Marshal(result)
		if e != nil {
			return nil, e
		}
		*m.results = append(*m.results, b)
	}
	return result, nil
}

type routingResolver struct {
	delegate resolution.Resolver
	out      *sageresolution.RoutingResult
}

func (r routingResolver) Resolve(ctx context.Context, id did.DID, o resolution.ResolutionOptions) resolution.Result {
	r.out.ResolveInputs = append(r.out.ResolveInputs, id.String())
	b, e := json.Marshal(o)
	if e != nil {
		r.out.CaptureError = e.Error()
	}
	r.out.ResolveOptions = append(r.out.ResolveOptions, b)
	return r.delegate.Resolve(ctx, id, o)
}
func (*Subject) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	out := sageresolution.RoutingResult{Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Request: q, ResolveInputs: []string{}, ResolveOptions: [][]byte{}, DriverOptions: [][]byte{}}
	if q.Document.MediaType != "application/did" || (q.Request.Function != "resolve" && q.Request.Function != "dereference") {
		return out, errors.New("requires literal application/did and an explicit library routing operation")
	}
	registry, e := method.NewRegistry(literalRoutingMethod{body: q.Document.Data, calls: &out.DriverOptions, inputs: &out.DriverInputs, results: &out.DriverResults})
	if e != nil {
		return out, e
	}
	p := producer.New()
	r, e := resolver.New(registry, consumer.New(), p)
	if e != nil {
		return out, e
	}
	observed := routingResolver{r, &out}
	ro, do := nativeOptions(q.Request)
	if q.Request.Function == "resolve" {
		out.Operation = "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve"
		out.Options, e = json.Marshal(ro)
		if e != nil {
			return out, e
		}
		id, e := did.Parse(q.Request.Input)
		if e != nil {
			return out, e
		}
		result := observed.Resolve(ctx, id, ro)
		capture := sageresolution.Result{Raw: result.Raw, HasContent: result.Document != nil}
		if result.Document != nil {
			capture.ReturnedID = result.Document.ID().String()
			capture.ContentKind = "document"
			capture.Snapshot, e = documentSnapshot(result.Document)
			if e != nil {
				return out, e
			}
		}
		if result.Document != nil {
			out.DataModel, out.Entries, out.CaptureError = captureMaps(result.Document)
		}
		out.Result, e = nativeResult(capture, result.ResolutionMetadata, result.DocumentMetadata)
		return out, e
	}
	out.Operation = "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference"
	out.Options, e = json.Marshal(do)
	if e != nil {
		return out, e
	}
	d, e := dereferencer.New(observed, p)
	if e != nil {
		return out, e
	}
	url, e := did.ParseURL(q.Request.Input)
	if e != nil {
		return out, e
	}
	result := d.Dereference(ctx, url, do)
	out.Result, e = dereferenceResult(sageresolution.Result{}, result.DereferencingMetadata, result.ContentStream, result.ContentMetadata)
	if doc, ok := result.ContentStream.(*document.Document); ok {
		model, entries, captureError := captureMaps(doc)
		out.DataModel = append([]byte(nil), model...)
		out.Entries = append([]byte(nil), entries...)
		if captureError != "" {
			out.CaptureError = captureError
		}
	}
	return out, e
}
