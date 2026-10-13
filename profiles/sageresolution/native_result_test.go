package sageresolution

import (
	"encoding/json"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func successResultScenario() resultScenario {
	return resultScenario{request: Request{Function: "resolve", Input: "did:sage:web:x:a", Accept: "application/did"}}
}
func errorResultScenario(branch, keyword string) resultScenario {
	return resultScenario{request: Request{Function: "resolve", Input: "did:sage:web:x:missing"}, branch: branch, errorKeyword: keyword}
}
func nativeFailure(keyword string) Result {
	return Result{Metadata: json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#` + keyword + `"}}`), ContentMetadata: json.RawMessage(`{}`)}
}
func TestNativeResultSuccessAndConditionalInactiveMarker(t *testing.T) {
	s := successResultScenario()
	r := nativeSchemaFixture("did-1.1")
	for _, o := range judgeNativeResult(r, s, "original") {
		want := core.Pass
		if o.Statement == resolutionPrefix+"resolving.5" || o.Statement == resolutionPrefix+"did-document-metadata.7" {
			want = core.NotApplicable
		}
		if o.Verdict != want || o.Input != "original" || o.Observed == "" {
			t.Fatal(o)
		}
	}
	for _, md := range []struct {
		raw  string
		want core.Verdict
	}{{`{"deactivated":false}`, core.Pass}, {`{"deactivated":true}`, core.Fail}, {`{"deactivated":null}`, core.Fail}, {`{"deactivated":"false"}`, core.Fail}} {
		r.ContentMetadata = json.RawMessage(md.raw)
		if got := nativeVerdict(judgeNativeResult(r, s, ""), "did-document-metadata.7"); got != md.want {
			t.Fatal(md, got)
		}
	}
	for _, change := range []func(*Result){
		func(r *Result) { r.HasContent = false }, func(r *Result) { r.ContentKind = "verification-method" }, func(r *Result) { r.ReturnedID = "did:example:other" },
		func(r *Result) {
			r.Metadata = json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		},
		func(r *Result) { r.Snapshot = json.RawMessage(`{"id":"did:example:other"}`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{"id":"not-a-did"}`) },
	} {
		r = nativeSchemaFixture("did-1.1")
		change(&r)
		if nativeVerdict(judgeNativeResult(r, s, ""), "resolving.1") != core.Fail {
			t.Fatal("invalid successful document")
		}
	}
}
func TestNativeErrorBranchesHaveIndependentNegativeControls(t *testing.T) {
	for _, tc := range []struct{ branch, keyword, whole, nullDoc, empty string }{
		{"invalid", "INVALID_DID", "resolving-algorithm.1", "resolving-algorithm.3", "resolving-algorithm.4"},
		{"method", "METHOD_NOT_SUPPORTED", "resolving-algorithm.5", "resolving-algorithm.7", "resolving-algorithm.8"},
		{"missing", "NOT_FOUND", "resolving-algorithm.18", "resolving-algorithm.20", "resolving-algorithm.21"},
	} {
		s := errorResultScenario(tc.branch, tc.keyword)
		r := nativeFailure(tc.keyword)
		for _, o := range judgeNativeResult(r, s, "original") {
			if o.Verdict != core.Pass || o.Input != "original" || o.Observed == "" {
				t.Fatal(o)
			}
		}
		r = nativeFailure("INTERNAL_ERROR")
		obs := judgeNativeResult(r, s, "")
		if nativeVerdict(obs, tc.whole) != core.Fail || nativeVerdict(obs, tc.nullDoc) != core.Pass || nativeVerdict(obs, tc.empty) != core.Pass {
			t.Fatal("error type coupled to null fields", obs)
		}
		if tc.branch == "method" && nativeVerdict(obs, "resolving-algorithm.6") != core.Fail {
			t.Fatal("method error type")
		}
		r = nativeFailure(tc.keyword)
		r.HasContent = true
		if obs = judgeNativeResult(r, s, ""); nativeVerdict(obs, tc.whole) != core.Fail || nativeVerdict(obs, tc.nullDoc) != core.Fail || nativeVerdict(obs, tc.empty) != core.Pass {
			t.Fatal("nonnull document", obs)
		}
		r = nativeFailure(tc.keyword)
		r.ContentMetadata = json.RawMessage(`{"unexpected":true}`)
		if obs = judgeNativeResult(r, s, ""); nativeVerdict(obs, tc.whole) != core.Fail || nativeVerdict(obs, tc.nullDoc) != core.Pass || nativeVerdict(obs, tc.empty) != core.Fail {
			t.Fatal("nonempty metadata", obs)
		}
		r = nativeFailure(tc.keyword)
		r.Metadata = json.RawMessage(`{}`)
		if obs = judgeNativeResult(r, s, ""); nativeVerdict(obs, "resolving.4") != core.Fail || nativeVerdict(obs, "resolving.5") != core.Fail {
			t.Fatal("error must not disappear", obs)
		}
	}
	for _, raw := range []string{`{"error":null}`, `{"error":7}`, `{"error":{}}`, `{"error":{"type":7}}`, `{"error":{"type":"relative"}}`} {
		r := nativeFailure("NOT_FOUND")
		r.Metadata = json.RawMessage(raw)
		if nativeVerdict(judgeNativeResult(r, errorResultScenario("", "NOT_FOUND"), ""), "resolving.5") != core.Fail {
			t.Fatal(raw)
		}
	}
}
func TestNativeNullDocumentCaptureAndUnusableObservations(t *testing.T) {
	if !nativeNullDocument(Result{}) || !nativeNullDocument(Result{Snapshot: json.RawMessage(`null`)}) {
		t.Fatal("null forms")
	}
	for _, r := range []Result{{HasContent: true}, {ReturnedID: "stale"}, {ContentKind: "document"}, {Snapshot: json.RawMessage(`{}`)}, {Snapshot: json.RawMessage(`{`)}} {
		if nativeNullDocument(r) {
			t.Fatal(r)
		}
	}
	for _, change := range []func(*Result){
		func(r *Result) { r.Metadata = json.RawMessage(`null`) }, func(r *Result) { r.Metadata = json.RawMessage(`{`) },
		func(r *Result) { r.ContentMetadata = json.RawMessage(`{"x":1,"x":2}`) }, func(r *Result) { r.Raw = nil; r.Snapshot = json.RawMessage(`{`) },
		func(r *Result) { r.Exchange = &core.HTTPExchange{} }, func(r *Result) { r.Native = &NativeObservation{} },
	} {
		r := nativeFailure("NOT_FOUND")
		change(&r)
		for _, o := range judgeNativeResult(r, errorResultScenario("missing", "NOT_FOUND"), "original") {
			if o.Verdict != core.Error || o.Input != "original" {
				t.Fatal(o)
			}
		}
	}
}
