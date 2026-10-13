package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"strings"
	"testing"
)

func contractControl(f contractFixture) ContractResult {
	q := f.Request.Request
	options := map[string]any{}
	for k, v := range q.Options {
		options[k] = v
	}
	if q.Accept != "" {
		options["accept"] = q.Accept
	}
	if q.Relationship != "" {
		options["verificationRelationship"] = q.Relationship
	}
	ob, _ := json.Marshal(options)
	ib, _ := json.Marshal(q.Input)
	o := ContractResult{Operation: "github.com/sage-x-project/did-go/advanced/sage.Resolver." + map[string]string{"resolve": "ResolveWithCode", "dereference": "DereferenceWithCode"}[q.Function], Identifier: ib, Options: ob}
	sign := map[string]any{"id": f.Record.DID + "#sign", "type": "JsonWebKey", "controller": f.Record.DID}
	agree := map[string]any{"id": f.Record.DID + "#agree", "type": "JsonWebKey", "controller": f.Record.DID}
	d, _ := json.Marshal(map[string]any{"id": f.Record.DID, "verificationMethod": []any{sign, agree}, "authentication": []string{f.Record.DID + "#sign"}})
	o.Result = Result{Metadata: []byte(`{"contentType":"application/did"}`), ContentMetadata: []byte(`{"versionId":"7"}`), HasContent: true, ReturnedID: q.Input, ContentKind: "document", Snapshot: d}
	if q.Function == "dereference" {
		copy := o.Result
		copy.ReturnedID = f.Record.DID
		o.Reference = &copy
		if strings.Contains(q.Input, "#") {
			m := sign
			if strings.HasSuffix(q.Input, "#agree") {
				m = agree
			}
			o.Result.Snapshot, _ = json.Marshal(m)
			o.Result.ContentKind = "verification-method"
			o.Result.ContentMetadata = []byte(`{}`)
		}
	}
	if f.ErrorType != "" {
		titles := map[string]string{"zero-resolve": "Invalid DID", "zero-dereference": "Invalid DID URL", "missing-fragment": "Not found", "wrong-purpose": "Invalid relationship for verification method", "no-method": "Invalid verification method", "unsupported-media": "Feature not supported", "unsupported-deref-media": "Representation not supported"}
		details := map[string]string{"zero-resolve": "the DID is empty", "zero-dereference": "a DID URL to dereference is absolute", "missing-fragment": "no part of the DID document has the id " + q.Input, "wrong-purpose": q.Input + " is not in authentication", "no-method": "the DID URL has no fragment, so it does not dereference to a verification method", "unsupported-media": "no representation acceptable to \"text/html\" can be produced", "unsupported-deref-media": "no DID document representation is acceptable to text/html"}
		p := map[string]any{"type": f.ErrorType, "title": titles[f.Name], "detail": details[f.Name]}
		o.Problem, _ = json.Marshal(p)
		md, _ := json.Marshal(map[string]any{"error": p})
		o.Result = Result{Metadata: md, ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
		o.Reference = nil
		o.ProblemSerializer = "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
	}
	syncContractMetadata(&o)
	return o
}
func syncContractMetadata(o *ContractResult) {
	o.Metadata = MetadataResult{Resolution: SerializedMetadata{Serializer: "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON", Bytes: append([]byte{}, o.Result.Metadata...)}, Document: SerializedMetadata{Serializer: "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON", Bytes: append([]byte{}, o.Result.ContentMetadata...)}}
}
func changeProblem(o *ContractResult, key string, value any) {
	var p map[string]any
	_ = json.Unmarshal(o.Problem, &p)
	if value == nil {
		delete(p, key)
	} else {
		p[key] = value
	}
	o.Problem, _ = json.Marshal(p)
	o.Result.Metadata, _ = json.Marshal(map[string]any{"error": p})
	syncContractMetadata(o)
}
func TestContractAttributionAndOutcomeControls(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	fixtures := contractFixtures(rows)
	if len(fixtures) != 23 {
		t.Fatal(len(fixtures))
	}
	ids := map[string]bool{}
	for _, f := range fixtures {
		o := contractControl(f)
		if v := contractOutcome(f, o); v != core.Pass {
			t.Fatal(f.Name, v)
		}
		for _, obs := range judgeContract(f, o, "input") {
			ids[obs.Statement] = true
			if obs.Verdict != core.Pass {
				t.Fatal(f.Name, obs)
			}
		}
		changes := []func(*ContractResult){func(x *ContractResult) { x.Operation = "other" }, func(x *ContractResult) { x.CaptureError = "lost" }, func(x *ContractResult) { x.Identifier = []byte(`null`) }, func(x *ContractResult) { x.Identifier = []byte(`"other"`) }, func(x *ContractResult) { x.Options = []byte(`null`) }, func(x *ContractResult) { x.Options = []byte(`{"extra":true}`) }, func(x *ContractResult) { x.Metadata.Document.Serializer = "other" }, func(x *ContractResult) { x.Metadata.Resolution.Serializer = "other" }, func(x *ContractResult) { x.Metadata.Resolution.Error = "lost" }, func(x *ContractResult) { x.Metadata.Document.Error = "lost" }, func(x *ContractResult) { x.Metadata.Resolution.Bytes = []byte(`{`) }, func(x *ContractResult) { x.Metadata.Document.Bytes = []byte(`[]`) }, func(x *ContractResult) { x.Metadata.Document.Bytes = []byte(`{"changed":true}`) }, func(x *ContractResult) { x.Result.Metadata = []byte(`{`) }, func(x *ContractResult) { x.Result.ContentMetadata = []byte(`[]`) }, func(x *ContractResult) { x.Result.Native = &NativeObservation{} }, func(x *ContractResult) { x.Result.Exchange = &core.HTTPExchange{} }}
		for _, change := range changes {
			x := contractControl(f)
			change(&x)
			if contractOutcome(f, x) == core.Pass {
				t.Fatal("attribution false PASS", f.Name)
			}
		}
		if f.ErrorType != "" {
			for _, change := range []func(*ContractResult){func(x *ContractResult) { x.Result.HasContent = true }, func(x *ContractResult) { x.Result.Metadata = []byte(`{}`); syncContractMetadata(x) }, func(x *ContractResult) { changeProblem(x, "type", "https://example.com/wrong") }, func(x *ContractResult) { x.Result.ContentMetadata = []byte(`{"extra":true}`); syncContractMetadata(x) }, func(x *ContractResult) { x.Reference = &Result{} }, func(x *ContractResult) { x.Result.Raw = []byte(`{}`) }} {
				x := contractControl(f)
				change(&x)
				if f.Request.Request.Function == "resolve" && string(x.Result.Raw) == "{}" {
					continue
				}
				if contractOutcome(f, x) == core.Pass {
					t.Fatal("error outcome false PASS", f.Name)
				}
			}
		} else {
			for _, change := range []func(*ContractResult){func(x *ContractResult) { x.Result.HasContent = false }, func(x *ContractResult) { x.Result.ReturnedID = "other" }, func(x *ContractResult) { x.Result.ContentKind = "other" }, func(x *ContractResult) { x.Result.Metadata = []byte(`{"error":{}}`); syncContractMetadata(x) }} {
				x := contractControl(f)
				change(&x)
				if contractOutcome(f, x) == core.Pass {
					t.Fatal("success false PASS", f.Name)
				}
			}
			if f.Request.Request.Function == "resolve" {
				x := contractControl(f)
				x.Reference = &Result{}
				if contractOutcome(f, x) == core.Pass {
					t.Fatal("extra ref")
				}
			} else {
				for _, change := range []func(*ContractResult){func(x *ContractResult) { x.Reference = nil }, func(x *ContractResult) { x.Reference.Metadata = []byte(`{`) }, func(x *ContractResult) { x.Reference.Metadata = []byte(`{"error":{}}`) }, func(x *ContractResult) { x.Reference.Snapshot = []byte(`{`) }, func(x *ContractResult) { x.Reference.Snapshot = []byte(`{"id":"other"}`) }, func(x *ContractResult) { x.Result.Snapshot = []byte(`{`) }, func(x *ContractResult) { x.Reference.ContentMetadata = []byte(`{`) }, func(x *ContractResult) {
					x.Reference.Snapshot = []byte(`{"id":"` + f.Record.DID + `","verificationMethod":[]}`)
				}} {
					x := contractControl(f)
					change(&x)
					if strings.Contains(f.Request.Request.Input, "#") && x.Reference != nil && string(x.Reference.ContentMetadata) == "{" {
						continue
					}
					if contractOutcome(f, x) == core.Pass {
						t.Fatal("reference false PASS", f.Name)
					}
				}
			}
		}
	}
	if len(ids) != 23 {
		t.Fatal(len(ids))
	}
}
func TestContractFragmentAuthorizationControls(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		if f.Name != "authorized-sign" {
			continue
		}
		for _, fragment := range []string{`"authentication":[]`, `"authentication":["other"]`, `"authentication":"other"`} {
			x := contractControl(f)
			x.Reference.Snapshot = []byte(`{"id":"` + f.Record.DID + `","verificationMethod":[{"controller":"` + f.Record.DID + `","id":"` + f.Record.DID + `#sign","type":"JsonWebKey"}],` + fragment + `}`)
			if contractOutcome(f, x) == core.Pass {
				t.Fatal("unauthorized fragment")
			}
		}
		x := contractControl(f)
		x.Reference.Snapshot = []byte(`{"id":"` + f.Record.DID + `","verificationMethod":false}`)
		if contractOutcome(f, x) == core.Pass {
			t.Fatal("bad methods")
		}
	}
}
func TestContractProblemAndHumanRecommendations(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		if f.ErrorType == "" {
			continue
		}
		for _, change := range []func(*ContractResult){func(x *ContractResult) { x.ProblemSerializer = "synthetic" }, func(x *ContractResult) { x.Problem = []byte(`{`) }, func(x *ContractResult) { x.Problem = []byte(`{}`) }, func(x *ContractResult) { changeProblem(x, "type", "other") }, func(x *ContractResult) { changeProblem(x, "title", true) }, func(x *ContractResult) { changeProblem(x, "detail", true) }, func(x *ContractResult) { changeProblem(x, "instance", true) }, func(x *ContractResult) { changeProblem(x, "status", 99) }, func(x *ContractResult) { changeProblem(x, "status", 600) }, func(x *ContractResult) { changeProblem(x, "status", 400.5) }, func(x *ContractResult) { changeProblem(x, "status", "400") }} {
			x := contractControl(f)
			change(&x)
			if contractProblem(x) == core.Pass {
				t.Fatal("problem false PASS", f.Name)
			}
		}
		x := contractControl(f)
		changeProblem(&x, "status", 400)
		changeProblem(&x, "instance", "https://example.com/problem/1")
		if contractProblem(x) != core.Pass {
			t.Fatal("valid optional members")
		}
		changeProblem(&x, "instance", "relative")
		if contractProblem(x) != core.NotSupported {
			t.Fatal("unobserved URI-reference grammar")
		}
		for _, field := range []string{"title", "detail"} {
			id := resolutionPrefix + "errors.5"
			if field == "title" {
				id = resolutionPrefix + "errors.4"
			}
			for _, value := range []any{nil, "", "unreviewed explanation", false} {
				x := contractControl(f)
				changeProblem(&x, field, value)
				want := core.Fail
				if value == "unreviewed explanation" {
					want = core.NotSupported
				}
				if contractOutcome(f, x) != core.Pass {
					t.Fatal("recommendation polluted mandatory refusal")
				}
				if contractAdvisory(f, x, id) != want {
					t.Fatal("recommendation false PASS")
				}
				for _, o := range judgeContract(f, x, "input") {
					if o.Statement == id && o.Verdict != want {
						t.Fatal(o)
					}
				}
			}
		}
	}
	if contractAdvisory(contractFixture{}, ContractResult{Problem: []byte(`{`)}, resolutionPrefix+"errors.4") != core.Error {
		t.Fatal("invalid problem")
	}
}

type contractMock struct {
	noOperation
	fail bool
}

func (s contractMock) InspectContract(_ context.Context, r sageprojection.Record, q ContractRequest) (ContractResult, error) {
	if s.fail {
		return ContractResult{Operation: "partial"}, errors.New("observer failed")
	}
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		a, _ := json.Marshal(q)
		b, _ := json.Marshal(f.Request)
		if string(a) == string(b) && reflectRecord(r, f.Record) {
			return contractControl(f), nil
		}
	}
	return ContractResult{}, errors.New("unknown request")
}
func reflectRecord(a, b sageprojection.Record) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func TestContractDispatch(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendContractCases(&p, rows)
		want := 23
		if name == "did-core-1.0" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{contractMock{}, core.Pass}, {contractMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o)
					}
				}
			}
		}
	}
}

func reverseContractObject(raw []byte) []byte {
	v, _ := core.ParseJSON(raw)
	for i, j := 0, len(v.Object)-1; i < j; i, j = i+1, j-1 {
		v.Object[i], v.Object[j] = v.Object[j], v.Object[i]
	}
	b, _ := v.MarshalJSON()
	return b
}
func TestNativeContractObjectAndKnownSetOrder(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		x := contractControl(f)
		if f.ErrorType != "" {
			x.Problem = reverseContractObject(x.Problem)
			if contractProblem(x) != core.Pass {
				t.Fatal("problem member order")
			}
		} else {
			x.Result.Snapshot = reverseContractObject(x.Result.Snapshot)
			if x.Reference != nil {
				x.Reference.ContentMetadata = reverseContractObject(x.Reference.ContentMetadata)
				v, _ := core.ParseJSON(x.Reference.Snapshot)
				methods, ok := v.Get("verificationMethod")
				if ok {
					methods.Array[0], methods.Array[1] = methods.Array[1], methods.Array[0]
				}
				x.Reference.Snapshot, _ = v.MarshalJSON()
			}
		}
		for _, o := range judgeContract(f, x, "input") {
			if o.Verdict != core.Pass {
				t.Fatal("object/set order false FAIL", f.Name, o)
			}
		}
	}
}

func TestNativeContractClauseVerdictsStayIndependent(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		if f.ErrorType != "" {
			x := contractControl(f)
			changeProblem(&x, "type", "https://www.w3.org/ns/did#INTERNAL_ERROR")
			for _, id := range []string{"resolving.3", "dereferencing.2", "dereferencing.4", "dereferencing.5", "dereferencing.6", "dereferencing.7", "did-url-dereferencing-options.5", "errors.1"} {
				if f.Request.Request.Function == "resolve" && strings.HasPrefix(id, "dereferencing.") {
					continue
				}
				if contractClause(f, x, resolutionPrefix+id) != core.Pass {
					t.Fatal("different error type polluted", f.Name, id)
				}
			}
			if f.Name == "zero-dereference" {
				for _, id := range []string{"dereferencing-algorithm-resource.1", "dereferencing-algorithm-resource.2"} {
					if contractClause(f, x, resolutionPrefix+id) != core.Fail {
						t.Fatal("explicit required type not checked")
					}
				}
				for _, id := range []string{"dereferencing-algorithm-resource.3", "dereferencing-algorithm-resource.4"} {
					if contractClause(f, x, resolutionPrefix+id) != core.Pass {
						t.Fatal("type polluted other tuple member")
					}
				}
			}
			x = contractControl(f)
			changeProblem(&x, "title", false)
			if contractClause(f, x, resolutionPrefix+"errors.4") != core.Fail || contractClause(f, x, resolutionPrefix+"errors.5") != core.Pass || contractClause(f, x, resolutionPrefix+"errors.1") != core.Fail {
				t.Fatal("title polluted detail or RFC shape")
			}
			if f.Name == "unsupported-media" {
				if contractClause(f, x, resolutionPrefix+"errors.7") != core.Pass {
					t.Fatal("title polluted feature detail")
				}
				changeProblem(&x, "type", "https://www.w3.org/ns/did#INTERNAL_ERROR")
				if contractClause(f, x, resolutionPrefix+"errors.7") != core.NotApplicable {
					t.Fatal("feature conditional applicability")
				}
			}
			x = contractControl(f)
			changeProblem(&x, "detail", false)
			if contractClause(f, x, resolutionPrefix+"errors.4") != core.Pass || contractClause(f, x, resolutionPrefix+"errors.5") != core.Fail {
				t.Fatal("detail polluted title")
			}
			x = contractControl(f)
			x.Result.Metadata = []byte(`{}`)
			syncContractMetadata(&x)
			if contractClause(f, x, resolutionPrefix+"dereferencing.6") != core.Fail || contractClause(f, x, resolutionPrefix+"dereferencing.7") != core.Fail {
				t.Fatal("absent error metadata")
			}
		} else if strings.HasPrefix(f.Name, "document-") {
			x := contractControl(f)
			x.Result.ContentMetadata = []byte(`{"changed":true}`)
			syncContractMetadata(&x)
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.14") != core.Pass || contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.15") != core.Fail || contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.12") != core.Fail {
				t.Fatal("metadata comparison polluted document member")
			}
			x = contractControl(f)
			x.Result.HasContent = false
			if contractClause(f, x, resolutionPrefix+"dereferencing.11") != core.NotApplicable {
				t.Fatal("successful metadata condition")
			}
			x = contractControl(f)
			x.Result.Snapshot = []byte(`{`)
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.14") != core.Error {
				t.Fatal("invalid snapshot")
			}
			x = contractControl(f)
			x.Reference = nil
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.15") != core.Error {
				t.Fatal("missing reference")
			}
			x = contractControl(f)
			x.Reference.Metadata = []byte(`{"error":{}}`)
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.15") != core.Error {
				t.Fatal("failed reference")
			}
			x = contractControl(f)
			x.Reference.Snapshot = []byte(`{"id":"other"}`)
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.15") != core.Fail {
				t.Fatal("wrong reference")
			}
			x = contractControl(f)
			x.Reference.ContentMetadata = []byte(`{`)
			if contractClause(f, x, resolutionPrefix+"dereferencing-algorithm-resource.15") != core.Error {
				t.Fatal("bad reference metadata")
			}
			x = contractControl(f)
			x.Options = []byte(`{"other":true}`)
			if contractCapture(f, x) != core.Error {
				t.Fatal("observer mismatch marked violation")
			}
		}
		if contractClause(f, contractControl(f), "other") != core.Error {
			t.Fatal("unknown clause")
		}
	}
}

func TestNativeContractEmptyErrorIsNotRefusal(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, f := range contractFixtures(rows) {
		if f.ErrorType == "" {
			continue
		}
		for _, body := range []string{`{"error":null}`, `{"error":{}}`, `{"error":{"type":false}}`, `{"error":{"type":"unqualified"}}`} {
			x := contractControl(f)
			x.Result.Metadata = []byte(body)
			syncContractMetadata(&x)
			for _, id := range []string{"resolving.2", "dereferencing.4", "did-url-dereferencing-options.5", "dereferencing.3"} {
				if (id == "resolving.2" || id == "dereferencing.4") && !f.Request.Zero {
					continue
				}
				if contractClause(f, x, resolutionPrefix+id) == core.Pass {
					t.Fatal("empty error mistaken for refusal", f.Name, id)
				}
			}
		}
	}
}
