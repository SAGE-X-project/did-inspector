package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/cache"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"time"
)

type cacheControlResolver struct{ calls *int }

func (r cacheControlResolver) Resolve(_ context.Context, d did.DID, _ resolution.ResolutionOptions) resolution.Result {
	*r.calls++
	return resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}, Raw: []byte(`{"id":"` + d.String() + `"}`)}
}
func (*Subject) InspectLibraryOperation(ctx context.Context, q sageresolution.LibraryOperationRequest) (sageresolution.LibraryOperationResult, error) {
	out := sageresolution.LibraryOperationResult{Request: q, Values: map[string]string{}, Results: []sageresolution.Result{}}
	switch q.Kind {
	case "parameters":
		out.ParseOperation = "github.com/sage-x-project/did-go/did.ParseURL"
		u, e := did.ParseURL(q.Input)
		if e != nil {
			out.Error = e.Error()
			return out, nil
		}
		out.Wire = u.String()
		out.Operation = "github.com/sage-x-project/did-go/did.DIDURL.Parameters"
		p, e := u.Parameters()
		if e != nil {
			out.Error = e.Error()
			return out, nil
		}
		for _, name := range p.Names() {
			out.Values[name], _ = p.Get(name)
		}
		if !p.VersionTime.IsZero() {
			out.VersionTime = p.VersionTime.Format(time.RFC3339Nano)
		}
	case "cache":
		out.Operation = "github.com/sage-x-project/did-go/resolution/cache.Resolver.Resolve"
		d, e := did.Parse(q.Input)
		if e != nil {
			return out, e
		}
		options := []cache.Option{}
		if q.Refuse {
			options = append(options, cache.RefuseNoCache())
		}
		r, e := cache.New(cacheControlResolver{&out.Calls}, options...)
		if e != nil {
			return out, e
		}
		for _, noCache := range []bool{false, true, false} {
			result := r.Resolve(ctx, d, resolution.ResolutionOptions{Accept: "application/did", NoCache: noCache})
			captured, e := nativeResult(sageresolution.Result{Raw: result.Raw}, result.ResolutionMetadata, result.DocumentMetadata)
			if e != nil {
				return out, e
			}
			out.Results = append(out.Results, captured)
		}
	default:
		return out, errors.New("unsupported independent library operation")
	}
	return out, nil
}
