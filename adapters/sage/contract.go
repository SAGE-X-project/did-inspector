package sage

import (
	"context"
	"encoding/json"
	"errors"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// InspectContract captures actual typed input/options before calling the
// pinned SAGE resolver. It preserves original serializer errors and problems;
// the additional resolve comparison is explicitly separate from dereferencing.
func (*Subject) InspectContract(ctx context.Context, in sageprojection.Record, q sageresolution.ContractRequest) (sageresolution.ContractResult, error) {
	out := sageresolution.ContractResult{}
	req := q.Request
	if (req.Function != "resolve" && req.Function != "dereference") || req.HTTP != nil || req.NativeFunction != "" || (q.Zero && req.Input != "") {
		return out, errors.New("requires an explicit typed native contract input")
	}
	rec, e := resolutionRecord(in)
	if e != nil {
		return out, e
	}
	resolver, e := didsage.NewResolver(resolutionSource{rec, req.SourceFailure}, consumer.New(), producer.New())
	if e != nil {
		return out, e
	}
	ro, do := nativeOptions(req)
	var problem *resolution.Error
	var captureErr error
	if req.Function == "resolve" {
		var d did.DID
		if !q.Zero {
			d, e = did.Parse(req.Input)
			if e != nil {
				return out, e
			}
		}
		out.Operation = "github.com/sage-x-project/did-go/advanced/sage.Resolver.ResolveWithCode"
		out.Identifier, e = json.Marshal(d.String())
		captureErr = errors.Join(captureErr, e)
		out.Options, e = ro.MarshalJSON()
		captureErr = errors.Join(captureErr, e)
		res, code := resolver.ResolveWithCode(ctx, d, ro)
		out.Result = sageresolution.Result{HasContent: res.Document != nil, Raw: res.Raw, SageCode: string(code)}
		if res.Document != nil {
			out.Result.ReturnedID = res.Document.ID().String()
			out.Result.ContentKind = "document"
			out.Result.Snapshot, e = documentSnapshot(res.Document)
			captureErr = errors.Join(captureErr, e)
		}
		out.Result, e = nativeResult(out.Result, res.ResolutionMetadata, res.DocumentMetadata)
		captureErr = errors.Join(captureErr, e)
		out.Metadata = serializeMetadata(res.ResolutionMetadata, res.DocumentMetadata)
		problem = res.ResolutionMetadata.Error
	} else {
		var u did.DIDURL
		if !q.Zero {
			u, e = did.ParseURL(req.Input)
			if e != nil {
				return out, e
			}
		}
		out.Operation = "github.com/sage-x-project/did-go/advanced/sage.Resolver.DereferenceWithCode"
		out.Identifier, e = json.Marshal(u.String())
		captureErr = errors.Join(captureErr, e)
		out.Options, e = do.MarshalJSON()
		captureErr = errors.Join(captureErr, e)
		res, code := resolver.DereferenceWithCode(ctx, u, do)
		out.Result, e = dereferenceResult(sageresolution.Result{SageCode: string(code)}, res.DereferencingMetadata, res.ContentStream, res.ContentMetadata)
		captureErr = errors.Join(captureErr, e)
		out.Metadata = serializeMetadata(res.DereferencingMetadata, res.ContentMetadata)
		problem = res.DereferencingMetadata.Error
		if out.Result.HasContent && u.Path() == "" && !u.HasQuery() {
			reference, e := (&Subject{}).InspectResolution(ctx, in, sageresolution.Request{Function: "resolve", Input: u.DID().String(), Accept: req.Accept, SourceFailure: req.SourceFailure})
			captureErr = errors.Join(captureErr, e)
			out.Reference = &reference
		}
	}
	if problem != nil {
		out.ProblemSerializer = "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
		out.Problem, e = json.Marshal(problem)
		captureErr = errors.Join(captureErr, e)
	}
	if captureErr != nil {
		out.CaptureError = captureErr.Error()
	}
	return out, nil
}
