package sage

import (
	"context"
	"errors"

	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// InspectMetadata preserves direct pinned native 1.1 serializer calls. It does
// not repair returned metadata, run a subject validator or use a generic JSON
// encoder as evidence. Each structure keeps its own bytes and error.
func (s *Subject) InspectMetadata(ctx context.Context, in sageprojection.Record, q sageresolution.Request) (sageresolution.MetadataResult, error) {
	if (q.Function != "resolve" && q.Function != "dereference") || q.HTTP != nil || q.NativeFunction != "" {
		return sageresolution.MetadataResult{}, errors.New("requires an explicit native 1.1 metadata operation")
	}
	rec, err := resolutionRecord(in)
	if err != nil {
		return sageresolution.MetadataResult{}, err
	}
	r, err := didsage.NewResolver(resolutionSource{rec, q.SourceFailure}, consumer.New(), producer.New())
	if err != nil {
		return sageresolution.MetadataResult{}, err
	}
	ro, do := nativeOptions(q)
	if q.Function == "resolve" {
		result, code := r.ResolveString(ctx, q.Input, ro)
		out := serializeMetadata(result.ResolutionMetadata, result.DocumentMetadata)
		out.SageCode = string(code)
		return out, nil
	}
	u, err := did.ParseURL(q.Input)
	if err != nil {
		return sageresolution.MetadataResult{}, err
	}
	result, code := r.DereferenceWithCode(ctx, u, do)
	out := serializeMetadata(result.DereferencingMetadata, result.ContentMetadata)
	out.SageCode = string(code)
	return out, nil
}

func serializeMetadata(md resolution.ResolutionMetadata, dm document.Metadata) sageresolution.MetadataResult {
	out := sageresolution.MetadataResult{}
	out.Resolution.Serializer = "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON"
	var err error
	out.Resolution.Bytes, err = md.MarshalJSON()
	if err != nil {
		out.Resolution.Error = err.Error()
	}
	out.Document.Serializer = "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON"
	out.Document.Bytes, err = dm.MarshalJSON()
	if err != nil {
		out.Document.Error = err.Error()
	}
	return out
}
