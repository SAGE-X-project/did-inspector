package sageresolution

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func representationFixture() Result {
	r := nativeSchemaFixture("did-1.1")
	r.Raw = []byte(`{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:sage:web:x:a"}`)
	return r
}
func TestRepresentationUsesActualBytesAndIndependentChecks(t *testing.T) {
	for _, raw := range []string{`{"@context":"https://www.w3.org/ns/did/v1.1"}`, `{"@context":["https://www.w3.org/ns/did/v1.1","https://example.org/context",{"term":"https://example.org/term"},null]}`} {
		r := representationFixture()
		r.Raw = []byte(raw)
		for _, o := range judgeRepresentation(r, "unit") {
			if o.Verdict != core.Pass || o.Input != "unit" || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
	for _, tc := range []struct {
		raw            string
		present, valid core.Verdict
	}{{`{}`, core.Fail, core.Fail}, {`{"@context":"https://www.w3.org/ns/did/v1"}`, core.Pass, core.Fail}, {`{"@context":[]}`, core.Pass, core.Fail}, {`{"@context":[7]}`, core.Pass, core.Fail}, {`{"@context":{}}`, core.Pass, core.Fail}, {`{"@context":["https://www.w3.org/ns/did/v1.1",1.5]}`, core.Pass, core.NotSupported}} {
		r := representationFixture()
		r.Raw = []byte(tc.raw)
		o := judgeRepresentation(r, "unit")
		if o[0].Verdict != tc.present || o[1].Verdict != tc.valid || o[2].Verdict != core.Pass || o[3].Verdict != core.Pass {
			t.Fatal(tc, o)
		}
	}
	// The accessor snapshot does not serve as the oracle for serialized context.
	r := representationFixture()
	r.Snapshot = json.RawMessage(`{"@context":"wrong"}`)
	for _, o := range judgeRepresentation(r, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	for _, md := range []string{`{}`, `{"contentType":7}`, `{"contentType":"application/did+json"}`, `{"contentType":"application/did;broken"}`, `{"contentType":"application/did; charset=\"한글\""}`} {
		r := representationFixture()
		r.Metadata = json.RawMessage(md)
		o := judgeRepresentation(r, "unit")
		if o[0].Verdict != core.Pass || o[1].Verdict != core.Pass || o[2].Verdict != core.Fail || o[3].Verdict != core.Fail {
			t.Fatal(o)
		}
	}
	for _, mutate := range []func(*Result){func(r *Result) { r.HasContent = false }, func(r *Result) { r.Native = &NativeObservation{} }, func(r *Result) { r.Exchange = &core.HTTPExchange{} }, func(r *Result) { r.Metadata = json.RawMessage(`null`) }, func(r *Result) { r.Metadata = json.RawMessage(`{"error":null}`) }, func(r *Result) { r.Raw = []byte(`{"@context":"one","@context":"two"}`) }, func(r *Result) { r.Raw = []byte(`[]`) }, func(r *Result) { r.Raw = []byte{0xff} }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) }} {
		r := representationFixture()
		mutate(&r)
		for _, o := range judgeRepresentation(r, "unit") {
			if o.Verdict != core.Error || o.Input != "unit" {
				t.Fatal(o)
			}
		}
	}
}

func TestRepresentationAcceptsValidMediaTypeParameters(t *testing.T) {
	for _, metadata := range []string{`{"contentType":"Application/DID"}`, `{"contentType":"application/did; charset=utf-8"}`} {
		r := representationFixture()
		r.Metadata = json.RawMessage(metadata)
		for _, o := range judgeRepresentation(r, "unit") {
			if o.Verdict != core.Pass {
				t.Fatal(o)
			}
		}
	}
}
