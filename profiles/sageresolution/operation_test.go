package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"testing"
)

func operationControl(f operationFixture) []LibraryOperationResult {
	out := []LibraryOperationResult{}
	for i, q := range f.Requests {
		v := LibraryOperationResult{Request: q, Operation: "github.com/sage-x-project/did-go/did.DIDURL.Parameters", Values: map[string]string{}, Results: []Result{}}
		if q.Kind == "parameters" {
			v.ParseOperation = "github.com/sage-x-project/did-go/did.ParseURL"
			v.Wire = q.Input
			if i == 0 {
				v.Values = f.Values
				v.VersionTime = f.Time
			} else {
				v.Error = "normal literal refusal"
				if f.Name == "parameters-ascii" {
					v.Operation = ""
					v.Wire = ""
				}
			}
		} else {
			v.Operation = "github.com/sage-x-project/did-go/resolution/cache.Resolver.Resolve"
			v.Calls = 2
			if q.Refuse {
				v.Calls = 1
			}
			for j := 0; j < 3; j++ {
				r := Result{Metadata: []byte(`{"contentType":"application/did"}`), Raw: []byte(`{"id":"did:example:123"}`)}
				if q.Refuse && j == 1 {
					r = Result{Metadata: []byte(`{"error":{"type":"https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED","detail":"noCache not permitted; retry without noCache"}}`)}
				}
				v.Results = append(v.Results, r)
			}
		}
		out = append(out, v)
	}
	return out
}
func TestOperationLiteralControlsAndGuards(t *testing.T) {
	for _, f := range operationFixtures() {
		if judgeOperation(f, operationControl(f), "input")[0].Verdict != core.Pass {
			t.Fatal(f.Name)
		}
		for _, change := range []func([]LibraryOperationResult){func(v []LibraryOperationResult) { v[0].Operation = "other" }, func(v []LibraryOperationResult) { v[0].Request.Input = "other" }, func(v []LibraryOperationResult) { v[0].Error = "unexpected" }} {
			v := operationControl(f)
			change(v)
			if judgeOperation(f, v, "input")[0].Verdict == core.Pass {
				t.Fatal("false PASS", f.Name)
			}
		}
		if judgeOperation(f, nil, "input")[0].Verdict != core.Error {
			t.Fatal("missing calls")
		}
		bad := f
		bad.Name = "unanchored"
		if judgeOperation(bad, operationControl(f), "input")[0].Verdict != core.Error {
			t.Fatal("unknown fixture")
		}
		if f.Requests[0].Kind == "parameters" {
			for _, change := range []func([]LibraryOperationResult){func(v []LibraryOperationResult) { v[0].Wire = "other" }, func(v []LibraryOperationResult) { v[0].Values = map[string]string{} }, func(v []LibraryOperationResult) { v[0].VersionTime = "other" }, func(v []LibraryOperationResult) { v[1].Error = "" }, func(v []LibraryOperationResult) { v[1].Values = map[string]string{"unexpected": "value"} }, func(v []LibraryOperationResult) { v[1].VersionTime = "other" }} {
				v := operationControl(f)
				change(v)
				if judgeOperation(f, v, "input")[0].Verdict == core.Pass {
					t.Fatal(f.Name)
				}
			}
		} else {
			for _, change := range []func([]LibraryOperationResult){func(v []LibraryOperationResult) { v[0].Calls = 1 }, func(v []LibraryOperationResult) { v[0].Results = nil }, func(v []LibraryOperationResult) { v[0].Results[0].Metadata = []byte(`{`) }, func(v []LibraryOperationResult) { v[1].Results[1].Metadata = []byte(`{"error":null}`) }, func(v []LibraryOperationResult) { v[1].Results[1].Raw = []byte(`{}`) }, func(v []LibraryOperationResult) { v[0].Results[0].Raw = []byte(`{}`) }} {
				v := operationControl(f)
				change(v)
				if judgeOperation(f, v, "input")[0].Verdict == core.Pass {
					t.Fatal("false cache PASS")
				}
			}
		}
	}
}

type operationMock struct {
	noOperation
	fail bool
}

func (s operationMock) InspectLibraryOperation(_ context.Context, q LibraryOperationRequest) (LibraryOperationResult, error) {
	if s.fail {
		return LibraryOperationResult{}, errors.New("failed observer")
	}
	for _, f := range operationFixtures() {
		for i, r := range f.Requests {
			if r == q {
				return operationControl(f)[i], nil
			}
		}
	}
	return LibraryOperationResult{}, errors.New("unknown literal")
}
func TestOperationDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendOperationCases(&p)
		if name != "did-1.1" && len(p.Cases) != 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			if !strings.Contains(c.ID, "remaining-operation-") {
				t.Fatal(c.ID)
			}
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{operationMock{}, core.Pass}, {operationMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestCacheExplanationRequiresSemanticReview(t *testing.T) {
	f := operationFixtures()[2]
	v := operationControl(f)
	v[1].Results[1].Metadata = []byte(`{"error":{"type":"https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED","detail":"A fresh lookup is disabled. Retry using the stored result."}}`)
	if judgeOperation(f, v, "input")[0].Verdict != core.NotSupported {
		t.Fatal("unreviewed wording classified as nonconformant")
	}
	v[1].Results[1].Metadata = []byte(`{"error":{"type":"https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED"}}`)
	if judgeOperation(f, v, "input")[0].Verdict != core.Fail {
		t.Fatal("missing explanation")
	}
}
