package sage

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func TestPipelinePassivelyCapturesActualResolver(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	for _, record := range rows {
		q := sageresolution.Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		captured, err := s.InspectPipeline(t.Context(), record, q)
		if err != nil {
			t.Fatal(err)
		}
		direct, err := s.InspectResolution(t.Context(), record, q)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(captured.Result)
		b, _ := json.Marshal(direct)
		if !bytes.Equal(a, b) {
			t.Fatal("passive wrappers changed the native resolver result", string(a), string(b))
		}
		if record.State == "deactivated" {
			continue
		}
		if len(captured.Producer) != 1 || len(captured.Consumer) != 1 {
			t.Fatal(captured)
		}
		p, c := captured.Producer[0], captured.Consumer[0]
		if p.Operation != producerOperation || c.Operation != consumerOperation || p.Error != "" || c.Error != "" || p.CaptureError != "" || c.CaptureError != "" || !bytes.Equal(p.Output, c.Input) || !bytes.Equal(p.Output, direct.Raw) {
			t.Fatal(p, c)
		}
		if string(p.Entries) != "{}" || !bytes.Contains(c.Entries, []byte("@context")) || bytes.Contains(c.Model, []byte("@context")) {
			t.Fatal("pre/post entries conflated", p, c)
		}
	}
	bad := rows[0]
	bad.DID = "bad"
	if _, err := s.InspectPipeline(t.Context(), bad, sageresolution.Request{Function: "resolve", Input: "bad", Accept: "application/did"}); err == nil {
		t.Fatal("bad record")
	}
	for _, q := range []sageresolution.Request{{Function: "http"}, {Function: "resolve", Input: rows[0].DID, Accept: "application/did", NativeFunction: "resolve"}, {Function: "resolve", Input: rows[0].DID, Accept: "application/did", HTTP: &core.HTTPRequest{}}, {Function: "resolve", Input: rows[0].DID, Accept: "application/did", SourceFailure: "record.stale"}, {Function: "resolve", Input: rows[0].DID, Accept: "application/did", Options: map[string]any{"versionId": "7"}}, {Function: "resolve", Input: rows[0].DID, Accept: "application/did+json"}} {
		if _, err := s.InspectPipeline(t.Context(), rows[0], q); err == nil {
			t.Fatal("accepted mismatched scope", q)
		}
	}
}

// Delegation controls exist only in unit tests; no subject verdicts are supplied.
type pipelineProducerStub struct {
	d      *document.Document
	opts   representation.ProduceOptions
	output []byte
	err    error
}

func (p *pipelineProducerStub) Produce(d *document.Document, o representation.ProduceOptions) ([]byte, string, error) {
	p.d, p.opts = d, o
	return p.output, "fixture-media", p.err
}

type pipelineConsumerStub struct {
	input []byte
	media string
	opts  representation.ConsumeOptions
	d     *document.Document
	err   error
}

func (c *pipelineConsumerStub) Consume(b []byte, media string, o representation.ConsumeOptions) (*document.Document, representation.ConsumeInfo, error) {
	c.input, c.media, c.opts = b, media, o
	b[0] = '!'
	return c.d, representation.ConsumeInfo{DetectedVersion: spec.V11, DroppedTerms: []string{"undefined"}}, c.err
}
func TestPipelineDelegatesWithoutRepairAndDetachesBytes(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	rec, _ := resolutionRecord(rows[0])
	doc, e := didsage.Document(rec, didsage.DID11)
	if e != nil {
		t.Fatal(e)
	}
	delegateError := errors.New("delegate failure")
	for _, err := range []error{nil, delegateError} {
		output := []byte("actual-output")
		p := &pipelineProducerStub{output: output, err: err}
		calls := []sageresolution.ProductionCapture{}
		opts := representation.ProduceOptions{Version: spec.V11, JSONLD: true}
		got, media, e := (observedProducer{p, &calls}).Produce(doc, opts)
		if e != err || media != "fixture-media" || &got[0] != &output[0] || p.d != doc || p.opts != opts {
			t.Fatal("producer delegation changed")
		}
		output[0] = '!'
		if string(calls[0].Output) != "actual-output" {
			t.Fatal("producer capture aliases result")
		}
		b := []byte("original-input")
		c := &pipelineConsumerStub{d: doc, err: err}
		cc := []sageresolution.ConsumptionCapture{}
		co := representation.ConsumeOptions{Require: spec.V11, Strict: true}
		returned, info, e := (observedConsumer{c, &cc}).Consume(b, "actual-media", co)
		if returned != doc || e != err || c.opts != co || c.media != "actual-media" || &c.input[0] != &b[0] || info.DetectedVersion != spec.V11 {
			t.Fatal("consumer delegation changed")
		}
		if string(cc[0].Input) != "original-input" || cc[0].MediaType != "actual-media" || cc[0].Require != "1.1" || !cc[0].Strict || len(cc[0].DroppedTerms) != 1 {
			t.Fatal(cc)
		}
		info.DroppedTerms[0] = "changed"
		if cc[0].DroppedTerms[0] != "undefined" {
			t.Fatal("detected info aliases capture")
		}
	}
	if _, _, e := captureMaps(nil); e == "" {
		t.Fatal("nil document captured")
	}
}

func TestCaptureMapSerializationErrorsStayVisible(t *testing.T) {
	valid := core.NewDocument(core.M("value", core.String("actual")))
	bad := core.NewDocument(core.M("value", core.Number("invalid-number")))
	for _, pair := range [][2]core.DocumentJSON{{bad, valid}, {valid, bad}} {
		if _, _, err := serializeCaptureMaps(pair[0], pair[1]); err == "" {
			t.Fatal("capture marshal error hidden")
		}
	}
}
