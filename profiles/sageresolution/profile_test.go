package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/report"
	"net/http"
	"strings"
	"testing"
)

type stub struct{ err bool }

func (stub) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit-resolution"} }
func (stub) Supports(string, core.Capability) bool { return false }
func (s stub) InspectResolution(context.Context, sageprojection.Record, Request) (Result, error) {
	if s.err {
		return Result{}, errors.New("fixture execution failed")
	}
	return Result{Metadata: json.RawMessage(`{}`), ContentMetadata: json.RawMessage(`{}`)}, nil
}

func (s stub) InspectMetadata(context.Context, sageprojection.Record, Request) (MetadataResult, error) {
	if s.err {
		return MetadataResult{}, errors.New("fixture metadata execution failed")
	}
	return MetadataResult{}, nil
}

func (s stub) InspectPipeline(context.Context, sageprojection.Record, Request) (PipelineResult, error) {
	if s.err {
		return PipelineResult{}, errors.New("fixture pipeline execution failed")
	}
	return PipelineResult{}, nil
}

func (s stub) InspectConsumption(context.Context, ConsumptionRequest) (ConsumptionCapture, error) {
	if s.err {
		return ConsumptionCapture{}, errors.New("fixture consumer execution error")
	}
	return ConsumptionCapture{}, nil
}

func (s stub) InspectTypedProduction(context.Context, TypedProductionRequest) (TypedProductionResult, error) {
	if s.err {
		return TypedProductionResult{}, errors.New("fixture typed production unavailable")
	}
	return TypedProductionResult{}, nil
}

func (s stub) InspectTypedConsumption(context.Context, ConsumptionRequest) (TypedConsumptionResult, error) {
	if s.err {
		return TypedConsumptionResult{}, errors.New("fixture typed consumer unavailable")
	}
	return TypedConsumptionResult{}, nil
}

type noOperation struct{}

func (noOperation) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "missing"} }
func (noOperation) Supports(string, core.Capability) bool { return false }
func (s stub) InspectSyntax(_ context.Context, q SyntaxRequest) (SyntaxResult, error) {
	if s.err {
		return SyntaxResult{}, errors.New("fixture syntax failure")
	}
	return SyntaxResult{}, nil
}
func (s stub) InspectCodec(_ context.Context, q CodecRequest) (CodecResult, error) {
	if s.err {
		return CodecResult{}, errors.New("fixture codec failure")
	}
	return CodecResult{}, nil
}
func (s stub) InspectClient(_ context.Context, _ sageprojection.Record, q ClientRequest) (ClientResult, error) {
	if s.err {
		return ClientResult{}, errors.New("fixture client failure")
	}
	return ClientResult{}, nil
}
func (s stub) InspectRetrieval(_ context.Context, _ sageprojection.Record, q RetrievalRequest) (RetrievalResult, error) {
	if s.err {
		return RetrievalResult{}, errors.New("fixture retrieval failure")
	}
	return RetrievalResult{}, nil
}
func (s stub) InspectBaseContext(context.Context) (BaseContextResult, error) {
	if s.err {
		return BaseContextResult{}, errors.New("fixture context failed")
	}
	return BaseContextResult{}, nil
}
func TestProfileScopeAndUnavailable(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p, e := Profile(name)
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range []core.Subject{noOperation{}, stub{err: true}, stub{}} {
			result, e := (core.Runner{}).Run(t.Context(), p, s)
			if e != nil {
				t.Fatal(e)
			}
			in, e := report.InputFor(p, result, "unit")
			if e != nil {
				t.Fatal(e)
			}
			r := report.Build(in)
			if r.Totals.NotRun == 0 {
				t.Fatal("unobserved statements promoted")
			}
			for _, c := range result.Cases {
				for _, o := range c.Observations {
					if _, ok := s.(noOperation); ok && o.Verdict != core.NotSupported {
						t.Fatal(o)
					}
					if v, ok := s.(stub); ok && v.err && o.Verdict != core.Error {
						t.Fatal(o)
					}
					if v, ok := s.(stub); ok && !v.err && len(o.Input) == 0 {
						t.Fatal("lost input")
					}
				}
			}
		}
	}
	if _, e := Profile("other"); e == nil {
		t.Fatal("profile")
	}
	original := caseBytes
	defer func() { caseBytes = original }()
	for _, b := range []string{`{`, `[{"profile":"did-1.1","record":-1}]`, `[{"profile":"did-1.1","record":99}]`, `[{"profile":"did-1.1","record":0,"request":{"function":"http","http_method":"BAD"}}]`} {
		caseBytes = []byte(b)
		if _, e := Profile("did-1.1"); e == nil {
			t.Fatal(b)
		}
	}
	if contains([]string{"a"}, "b") {
		t.Fatal("contains")
	}
}
func native() Result {
	return Result{Metadata: json.RawMessage(`{}`), ContentMetadata: json.RawMessage(`{"versionId":"7"}`), HasContent: true, ReturnedID: "did:sage:web:x:a", ContentKind: "verification-method", Snapshot: json.RawMessage(`{"id":"did:sage:web:x:a"}`), Raw: []byte(`{"id":"did:sage:web:x:a"}`)}
}
func TestNativeChecksPositiveAndNegative(t *testing.T) {
	for _, tc := range []struct {
		name   string
		value  any
		modify func(*Result)
	}{
		{"success", nil, func(r *Result) { r.HasContent = false }},
		{"id", "did:sage:web:x:a", func(r *Result) { r.ReturnedID = "did:sage:web:x:other" }},
		{"fragment", "did:sage:web:x:a", func(r *Result) { r.ContentKind = "document" }},
		{"metadata-structure", nil, func(r *Result) { r.HasContent = false }},
		{"no-content-type", nil, func(r *Result) { r.Metadata = json.RawMessage(`{"contentType":"application/did"}`) }},
		{"representation", "application/did", func(r *Result) { r.Raw = []byte(`{"id":4}`) }},
	} {
		good := native()
		if tc.name == "representation" {
			good.Metadata = json.RawMessage(`{"contentType":"application/did"}`)
		}
		for _, bad := range []bool{false, true} {
			r := good
			if bad {
				tc.modify(&r)
			}
			obs := judge(r, []expected{{Check: tc.name, Value: tc.value, Statements: []string{"s"}}}, "input")
			if (obs[0].Verdict == core.Pass) == bad {
				t.Fatal(tc.name, bad, obs)
			}
		}
	}
	for _, v := range []string{"notFound", "internalError", "NOT_FOUND"} {
		errorValue := v
		if v == "NOT_FOUND" {
			errorValue = "https://www.w3.org/ns/did#NOT_FOUND"
		}
		md, _ := json.Marshal(map[string]any{"error": errorValue})
		if v == "NOT_FOUND" {
			md = []byte(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		}
		r := Result{Metadata: md, ContentMetadata: json.RawMessage(`{}`)}
		id := "res10-crd20261001#resolving.5"
		if v != "NOT_FOUND" {
			id = "core10#did-resolution-metadata.5"
		}
		if judge(r, []expected{{Check: "error", Value: v, Statements: []string{id}}, {Check: "failed-no-content", Statements: []string{id}}}, "")[0].Verdict != core.Pass {
			t.Fatal(v)
		}
		r.HasContent = true
		if judge(r, []expected{{Check: "failed-no-content", Statements: []string{id}}}, "")[0].Verdict != core.Fail {
			t.Fatal("failed content")
		}
	}
	r := Result{Metadata: json.RawMessage(`{}`), ContentMetadata: json.RawMessage(`{"deactivated":true}`)}
	if judge(r, []expected{{Check: "deactivated", Statements: []string{"s"}}}, "")[0].Verdict != core.Pass {
		t.Fatal("deactivated")
	}
	r.ContentMetadata = json.RawMessage(`{"deactivated":false}`)
	if judge(r, []expected{{Check: "deactivated", Statements: []string{"s"}}}, "")[0].Verdict != core.Fail {
		t.Fatal("deactivated state")
	}
	for _, field := range []string{"metadata", "content"} {
		r := native()
		if field == "metadata" {
			r.Metadata = json.RawMessage(`{`)
		} else {
			r.ContentMetadata = json.RawMessage(`{"x":1,"x":2}`)
		}
		if judge(r, []expected{{Check: "success", Statements: []string{"s"}}}, "")[0].Verdict != core.Error {
			t.Fatal("malformed result")
		}
	}
	if _, e := check(native(), core.DocumentJSON{}, core.DocumentJSON{}, expected{Check: "bad"}); e == nil {
		t.Fatal("unknown check")
	}
}
func TestHTTPChecksRejectCorruptedResponses(t *testing.T) {
	for _, tc := range []struct {
		check, body, mt string
		value           any
		status          int
	}{
		{"tls", `{}`, "application/did", nil, 200},
		{"status", `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`, "application/problem+json", float64(404), 404},
		{"status", `{"didResolutionMetadata":{},"didDocument":null,"didDocumentMetadata":{"deactivated":true}}`, "application/did-resolution", float64(410), 410},
		{"resolution-form", `{"didResolutionMetadata":{},"didDocument":{"id":"did:sage:web:x:a"},"didDocumentMetadata":{"versionId":"7"}}`, "application/did-resolution", "did:sage:web:x:a", 200},
		{"dereference-form", `{"dereferencingMetadata":{},"contentStream":{"id":"did:sage:web:x:a#sign"},"contentMetadata":{}}`, "application/did-url-dereferencing", "did:sage:web:x:a#sign", 200},
		{"body-id", `{"id":"did:sage:web:x:a"}`, "application/did", "did:sage:web:x:a", 200},
		{"problem", `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`, "application/problem+json", nil, 404},
	} {
		ex := core.HTTPExchange{URL: "https://localhost/", TLS: true, Status: tc.status, Header: http.Header{"Content-Type": []string{tc.mt}}, Body: []byte(tc.body)}
		w := expected{Check: tc.check, Value: tc.value}
		good, e := checkHTTP(Result{Exchange: &ex}, w)
		if e != nil || !good {
			t.Fatal(tc.check, e)
		}
		switch tc.check {
		case "tls":
			ex.TLS = false
		case "status":
			ex.Status = 400
		default:
			ex.Body = []byte(`{"id":null}`)
		}
		if good, e = checkHTTP(Result{Exchange: &ex}, w); e != nil || good {
			t.Fatal("corruption", tc.check, e)
		}
		ex.Body = []byte(`{`)
		if tc.check != "tls" && tc.check != "status" {
			good, e = checkHTTP(Result{Exchange: &ex}, w)
			if e != nil || good {
				t.Fatal("malformed", tc.check)
			}
		}
	}
	if _, e := checkHTTP(Result{}, expected{Check: "tls"}); e == nil {
		t.Fatal("absent wire exchange")
	}
	if _, e := checkHTTP(Result{Exchange: &core.HTTPExchange{}}, expected{Check: "bad"}); e == nil {
		t.Fatal("unknown wire check")
	}
	// Wrong error/status pairing must not pass even if the expected status matches.
	ex := core.HTTPExchange{Status: 404, Header: http.Header{"Content-Type": []string{"application/problem+json"}}, Body: []byte(`{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}`)}
	if ok, _ := checkHTTP(Result{Exchange: &ex}, expected{Check: "status", Value: float64(404)}); ok {
		t.Fatal("mismatched error/status")
	}
	ex.Status = 200
	if ok, _ := checkHTTP(Result{Exchange: &ex}, expected{Check: "status", Value: float64(200)}); !ok {
		t.Fatal("successful status")
	}
}

func TestMetadataStructureAndMalformedErrors(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		id := "res10-crd20261001#resolving.9"
		if legacy {
			id = "core10#did-resolution.11"
		}
		r := native()
		r.ContentMetadata = json.RawMessage(`{}`)
		if judge(r, []expected{{Check: "metadata-structure", Statements: []string{id}}}, "")[0].Verdict != core.Pass {
			t.Fatal("optional metadata omitted")
		}
		for _, bad := range []string{`{"error":{}}`, `{"error":{"type":7}}`, `{"error":null}`, `{"error":7}`, `{"error":""}`, `{"error":"é"}`} {
			r.Metadata = json.RawMessage(bad)
			if judge(r, []expected{{Check: "success", Statements: []string{id}}}, "")[0].Verdict == core.Pass {
				t.Fatal("malformed error passed", bad, legacy)
			}
		}
	}
	ex := core.HTTPExchange{Status: 200, Header: http.Header{"Content-Type": []string{"application/did-resolution"}}, Body: []byte(`{"didResolutionMetadata":{},"didDocument":{"id":"did:sage:web:x:a"},"didDocumentMetadata":{}}`)}
	w := expected{Check: "resolution-form", Value: "did:sage:web:x:a"}
	if ok, _ := checkHTTP(Result{Exchange: &ex}, w); !ok {
		t.Fatal("empty metadata rejected")
	}
	ex.Body = []byte(`{"didResolutionMetadata":{},"didDocument":{"id":"did:sage:web:x:other"},"didDocumentMetadata":{}}`)
	if ok, _ := checkHTTP(Result{Exchange: &ex}, w); ok {
		t.Fatal("wrong response DID")
	}
	ex.Body = []byte(`{"didResolutionMetadata":{"error":{}},"didDocument":{"id":"did:sage:web:x:a"},"didDocumentMetadata":{}}`)
	if ok, _ := checkHTTP(Result{Exchange: &ex}, w); ok {
		t.Fatal("error with success content")
	}
	ex.Status = 410
	ex.Body = []byte(`{"didResolutionMetadata":{},"didDocument":null,"didDocumentMetadata":{"deactivated":true}}`)
	if ok, _ := checkHTTP(Result{Exchange: &ex}, w); !ok {
		t.Fatal("deactivated response")
	}
}

func TestFailureChecksRemainIndependentlyAttributed(t *testing.T) {
	r := Result{Metadata: json.RawMessage(`{"error":"notFound"}`), ContentMetadata: json.RawMessage(`{"unexpected":true}`)}
	obs := judge(r, []expected{{Check: "failed-no-content", Statements: []string{"core10#did-resolution.8"}}, {Check: "failed-empty-metadata", Statements: []string{"core10#did-resolution.12"}}}, "")
	if obs[0].Verdict != core.Pass || obs[1].Verdict != core.Fail {
		t.Fatal(obs)
	}
	r.ContentMetadata = json.RawMessage(`{}`)
	r.HasContent = true
	obs = judge(r, []expected{{Check: "failed-no-content", Statements: []string{"core10#did-resolution.8"}}, {Check: "failed-empty-metadata", Statements: []string{"core10#did-resolution.12"}}}, "")
	if obs[0].Verdict != core.Fail || obs[1].Verdict != core.Pass {
		t.Fatal(obs)
	}
	for _, name := range []string{"raised-error", "stream-object", "content-type"} {
		r := native()
		r.Metadata = json.RawMessage(`{"contentType":"application/did"}`)
		if name == "raised-error" {
			r.Metadata = json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		}
		w := expected{Check: name, Value: "application/did"}
		d, _ := parse(r.Metadata)
		cm, _ := parse(r.ContentMetadata)
		if ok, e := check(r, d, cm, w); e != nil || !ok {
			t.Fatal(name, e)
		}
		r.Raw = []byte(`{`)
		r.Metadata = json.RawMessage(`{}`)
		d, _ = parse(r.Metadata)
		if ok, e := check(r, d, cm, w); e != nil || ok {
			t.Fatal("negative", name, e)
		}
	}
}

func TestOptionInputsAndHTTPParsingScopeArePreserved(t *testing.T) {
	p, e := Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	result, e := (core.Runner{}).Run(t.Context(), p, stub{})
	if e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, c := range result.Cases {
		if !strings.Contains(c.Case, "/http-options-") {
			continue
		}
		found++
		if len(c.Statements) != 1 || c.Statements[0] != "res10-crd20261001#bindings-https.2" {
			t.Fatal("parsing refusal attributed to resolver", c)
		}
		for _, o := range c.Observations {
			var input struct {
				Request Request `json:"request"`
			}
			if e = json.Unmarshal([]byte(o.Input), &input); e != nil || input.Request.HTTP == nil || len(input.Request.Options) == 0 {
				t.Fatal("lost options", e)
			}
			req := input.Request.HTTP
			if req.Method == "GET" && !strings.Contains(req.Target, "?") {
				t.Fatal("lost query", req)
			}
			if req.Method == "POST" && len(req.Body) == 0 {
				t.Fatal("lost body", req)
			}
		}
	}
	if found != 4 {
		t.Fatal("HTTP parsing scope", found)
	}
}

func (s stub) InspectContract(context.Context, sageprojection.Record, ContractRequest) (ContractResult, error) {
	if s.err {
		return ContractResult{}, errors.New("fixture contract failure")
	}
	return ContractResult{}, nil
}

func (s stub) InspectPolicy(context.Context, PolicyRequest) (PolicyResult, error) {
	if s.err {
		return PolicyResult{}, errors.New("fixture policy failure")
	}
	return PolicyResult{}, nil
}
