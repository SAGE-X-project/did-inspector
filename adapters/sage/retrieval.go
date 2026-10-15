package sage

import (
	"context"
	"encoding/json"
	"errors"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/relyingparty"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"time"
)

type retrievalDereferencer struct {
	delegate resolution.Dereferencer
	out      *sageresolution.RetrievalResult
}

func (d retrievalDereferencer) Dereference(ctx context.Context, u did.DIDURL, q resolution.DereferenceOptions) resolution.DereferenceResult {
	options, e := json.Marshal(q)
	result := d.delegate.Dereference(ctx, u, q)
	capture, f := dereferenceResult(sageresolution.Result{}, result.DereferencingMetadata, result.ContentStream, result.ContentMetadata)
	if err := errors.Join(e, f); err != nil {
		d.out.CaptureError = err.Error()
	}
	d.out.Calls = append(d.out.Calls, sageresolution.RetrievalCall{Input: u.String(), Options: options, Result: capture})
	return result
}

// InspectRetrieval observes the actual selected relying party and SAGE
// dereferencer. Actual errors.As problem objects are serialized unchanged;
// inspector does not construct security vocabulary URLs from Go errors.
func (*Subject) InspectRetrieval(ctx context.Context, in sageprojection.Record, q sageresolution.RetrievalRequest) (sageresolution.RetrievalResult, error) {
	out := sageresolution.RetrievalResult{Operation: "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod", Clock: 1800000000, Calls: []sageresolution.RetrievalCall{}}
	if q.Zero && q.Reference != "" {
		return out, errors.New("typed zero input must have no reference text")
	}
	purpose, e := vm.ParsePurpose(q.Purpose)
	if e != nil {
		return out, e
	}
	var ref did.DIDURL
	if !q.Zero {
		ref, e = did.ParseURL(q.Reference)
		if e != nil {
			return out, e
		}
	}
	if !q.Zero {
		parts := urlParts(ref)
		out.ParsedURL = &parts
	}
	out.Reference, out.Purpose = ref.String(), purpose.String()
	rec, e := resolutionRecord(in)
	if e != nil {
		return out, e
	}
	resolver, e := didsage.NewResolver(resolutionSource{rec, ""}, consumer.New(), producer.New())
	if e != nil {
		return out, e
	}
	_, options := nativeOptions(sageresolution.Request{Options: q.Options})
	rp, e := relyingparty.New(retrievalDereferencer{resolver, &out}, relyingparty.WithVersion(spec.V11), relyingparty.WithClock(func() time.Time { return time.Unix(out.Clock, 0).UTC() }), relyingparty.WithDereferenceOptions(options))
	if e != nil {
		return out, e
	}
	method, e := rp.VerificationMethod(ctx, ref, purpose)
	if e != nil {
		out.Error = e.Error()
		var problem *resolution.Error
		if errors.As(e, &problem) {
			out.ProblemSerializer = "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
			out.Problem, e = json.Marshal(problem)
			if e != nil {
				out.CaptureError = e.Error()
			}
		}
	}
	if method != nil {
		value, err := methodJSON(*method)
		if err != nil {
			return out, err
		}
		out.Method, e = value.MarshalJSON()
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
