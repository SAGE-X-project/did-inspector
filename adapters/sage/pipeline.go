package sage

import (
	"context"
	"errors"

	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

const producerOperation = "github.com/sage-x-project/did-go/producer.Producer.Produce"
const consumerOperation = "github.com/sage-x-project/did-go/consumer.Consumer.Consume"

func captureMaps(d *document.Document) (model, entries []byte, captureError string) {
	if d == nil {
		return nil, nil, "no actual document accessor maps"
	}
	m, err := documentJSON(d)
	if err != nil {
		return nil, nil, err.Error()
	}
	r, err := representationEntries(d)
	if err != nil {
		return nil, nil, err.Error()
	}
	return serializeCaptureMaps(m, r)
}
func serializeCaptureMaps(m, r core.DocumentJSON) (model, entries []byte, captureError string) {
	var err error
	model, err = m.MarshalJSON()
	if err != nil {
		return nil, nil, err.Error()
	}
	entries, err = r.MarshalJSON()
	if err != nil {
		return nil, nil, err.Error()
	}
	return model, entries, ""
}

type observedProducer struct {
	delegate representation.Producer
	calls    *[]sageresolution.ProductionCapture
}

func (p observedProducer) Produce(d *document.Document, opts representation.ProduceOptions) ([]byte, string, error) {
	model, entries, captureError := captureMaps(d)
	data, mediaType, err := p.delegate.Produce(d, opts)
	call := sageresolution.ProductionCapture{Operation: producerOperation, Model: model, Entries: entries, CaptureError: captureError,
		Version: opts.Version.String(), JSONLD: opts.JSONLD, IncludeSecret: opts.IncludeSecret, Output: append([]byte(nil), data...), MediaType: mediaType}
	if err != nil {
		call.Error = err.Error()
	}
	*p.calls = append(*p.calls, call)
	return data, mediaType, err
}

type observedConsumer struct {
	delegate representation.Consumer
	calls    *[]sageresolution.ConsumptionCapture
}

func (c observedConsumer) Consume(data []byte, mediaType string, opts representation.ConsumeOptions) (*document.Document, representation.ConsumeInfo, error) {
	input := append([]byte(nil), data...)
	d, info, err := c.delegate.Consume(data, mediaType, opts)
	call := sageresolution.ConsumptionCapture{Operation: consumerOperation, Input: input, MediaType: mediaType, Require: opts.Require.String(), Expected: opts.Expected.String(), Strict: opts.Strict,
		Version: info.DetectedVersion.String(), JSONLD: info.IsJSONLD, DroppedTerms: append([]string(nil), info.DroppedTerms...)}
	if err != nil {
		call.Error = err.Error()
	}
	call.Model, call.Entries, call.CaptureError = captureMaps(d)
	*c.calls = append(*c.calls, call)
	return d, info, err
}

// InspectPipeline passively observes the actual producer and consumer supplied
// to a fresh SAGE resolver. Delegated arguments, errors and return values are
// unchanged. No generic fixtures, validator findings or reconstructed expected
// documents replace these call-boundary observations.
func (s *Subject) InspectPipeline(ctx context.Context, in sageprojection.Record, q sageresolution.Request) (sageresolution.PipelineResult, error) {
	out := sageresolution.PipelineResult{}
	if q.Function != "resolve" || q.Input != in.DID || q.Accept != "application/did" || q.HTTP != nil || q.NativeFunction != "" || q.SourceFailure != "" || len(q.Options) != 0 {
		return out, errors.New("requires a default native application/did resolution of the fixture record")
	}
	rec, err := resolutionRecord(in)
	if err != nil {
		return out, err
	}
	r, err := didsage.NewResolver(resolutionSource{rec, ""}, observedConsumer{consumer.New(), &out.Consumer}, observedProducer{producer.New(), &out.Producer})
	if err != nil {
		return out, err
	}
	ro, _ := nativeOptions(q)
	res, code := r.ResolveString(ctx, q.Input, ro)
	native := sageresolution.Result{Raw: append([]byte(nil), res.Raw...), HasContent: res.Document != nil, SageCode: string(code)}
	if res.Document != nil {
		native.ReturnedID, native.ContentKind = res.Document.ID().String(), "document"
		native.Snapshot, err = documentSnapshot(res.Document)
		if err != nil {
			return out, err
		}
	}
	out.Result, err = nativeResult(native, res.ResolutionMetadata, res.DocumentMetadata)
	return out, err
}

// InspectConsumption probes the actual consumer selected by SAGE integration.
// This is an explicit library input boundary, not evidence for resolver or
// production ingress behavior. It preserves errors rather than converting them
// into synthesized resolution codes or validator verdicts.
func (s *Subject) InspectConsumption(_ context.Context, q sageresolution.ConsumptionRequest) (sageresolution.ConsumptionCapture, error) {
	if q.MediaType != "application/did" && q.MediaType != "application/did+json" {
		return sageresolution.ConsumptionCapture{}, errors.New("unsupported inspection media type")
	}
	calls := []sageresolution.ConsumptionCapture{}
	_, _, _ = (observedConsumer{consumer.New(), &calls}).Consume(q.Data, q.MediaType, representation.ConsumeOptions{})
	return calls[0], nil
}
