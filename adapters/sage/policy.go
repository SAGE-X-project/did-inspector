package sage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/relyingparty"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"time"
)

type policyDocumentFixture struct {
	doc         *document.Document
	nonDocument bool
}

func (d policyDocumentFixture) Dereference(_ context.Context, _ did.DIDURL, _ resolution.DereferenceOptions) resolution.DereferenceResult {
	if d.nonDocument {
		return resolution.DereferenceResult{ContentStream: "literal non-document fixture", DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "text/plain"}}
	}
	return resolution.DereferenceResult{ContentStream: d.doc, DereferencingMetadata: resolution.DereferencingMetadata{ContentType: "application/did"}}
}

// InspectPolicy consumes literal bytes and passes the actual returned document
// to the selected relying party via an explicit fixture dereferencer. It does
// not claim SAGE Source support or mutate a document to bypass validation.
func (*Subject) InspectPolicy(ctx context.Context, q sageresolution.PolicyRequest) (sageresolution.PolicyResult, error) {
	return ObservePolicy(ctx, q)
}

// ObservePolicy captures literal library calls without judging them. A caller
// using this observer directly must identify its actual subject independently;
// this function does not confer the pinned SAGE Subject identity.
func ObservePolicy(ctx context.Context, q sageresolution.PolicyRequest) (sageresolution.PolicyResult, error) {
	out := sageresolution.PolicyResult{Role: "literal library fixture; not SAGE registry Source", Retrieval: sageresolution.RetrievalResult{Calls: []sageresolution.RetrievalCall{}}, ClockValues: []string{}}
	if q.Document.MediaType != "application/did" || (q.Mode != "consume" && q.Mode != "retrieve") {
		return out, errors.New("requires an explicit library consumption or retrieval input")
	}
	calls := []sageresolution.ConsumptionCapture{}
	d, _, _ := (observedConsumer{consumer.New(), &calls}).Consume(q.Document.Data, q.Document.MediaType, representation.ConsumeOptions{})
	out.Consumer = calls[0]
	if d == nil {
		return out, nil
	}
	for _, m := range d.VerificationMethods() {
		w := sageresolution.ConsumedMethod{ID: m.ID.String()}
		if m.Expires != nil {
			w.Expires = &sageresolution.TypedValue{Kind: "datetime", Text: m.Expires.Format(time.RFC3339Nano)}
		}
		if m.Revoked != nil {
			w.Revoked = &sageresolution.TypedValue{Kind: "datetime", Text: m.Revoked.Format(time.RFC3339Nano)}
		}
		out.Methods = append(out.Methods, w)
	}
	if q.Mode == "consume" {
		return out, nil
	}
	ref, e := did.ParseURL(q.Reference)
	if e != nil {
		return out, e
	}
	purpose, e := vm.ParsePurpose(q.Purpose)
	if e != nil {
		return out, e
	}
	now, e := time.Parse(time.RFC3339Nano, q.Now)
	if e != nil {
		return out, e
	}
	_, options := nativeOptions(sageresolution.Request{Options: q.Options})
	out.Retrieval.Reference, out.Retrieval.Purpose = ref.String(), purpose.String()
	rp, e := relyingparty.New(retrievalDereferencer{policyDocumentFixture{d, q.NonDocument}, &out.Retrieval}, relyingparty.WithVersion(spec.V11), relyingparty.WithDereferenceOptions(options), relyingparty.WithClock(func() time.Time { out.ClockValues = append(out.ClockValues, now.Format(time.RFC3339Nano)); return now }))
	if e != nil {
		return out, e
	}
	out.Retrieval.Operation = "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod"
	method, e := rp.VerificationMethod(ctx, ref, purpose)
	if e != nil {
		out.Retrieval.Error = e.Error()
		var problem *resolution.Error
		if errors.As(e, &problem) {
			out.Retrieval.ProblemSerializer = "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
			out.Retrieval.Problem, e = json.Marshal(problem)
			if e != nil {
				out.CaptureError = e.Error()
			}
		}
	}
	if method != nil {
		value, e := methodJSON(*method)
		if e != nil {
			return out, e
		}
		out.Retrieval.Method, e = value.MarshalJSON()
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
