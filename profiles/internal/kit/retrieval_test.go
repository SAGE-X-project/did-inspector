package kit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// retriever is a scriptable verification method retriever and validator.
type retriever struct {
	res      core.RetrievalResult
	err      error
	findings []core.Finding
	valErr   error
	loadErr  error
}

func (r *retriever) Describe() core.SubjectInfo                   { return core.SubjectInfo{Name: "retriever"} }
func (r *retriever) Supports(string, core.Capability) bool        { return true }
func (r *retriever) LoadFixtureRegistry(*fixtures.Registry) error { return r.loadErr }
func (r *retriever) RetrieveVerificationMethod(context.Context, string, string, map[string]any) (core.RetrievalResult, error) {
	return r.res, r.err
}
func (r *retriever) ValidateVerificationMethod(core.DocumentJSON, string) ([]core.Finding, error) {
	return r.findings, r.valErr
}

func method(id string) *core.DocumentJSON {
	d := core.NewDocument(core.M("id", core.String(id)), core.M("type", core.String("Multikey")), core.M("controller", core.String("did:example:a")))
	return &d
}

func verdictList(obs []core.Observation) string {
	var parts []string
	for _, o := range obs {
		parts = append(parts, string(o.Verdict))
	}
	return strings.Join(parts, ",")
}

func TestRetrievalCases(t *testing.T) {
	want, _ := json.Marshal(map[string]string{"id": "#key-1", "type": "Multikey", "controller": "did:example:a"})
	f := RetrievalFile{Scenarios: []Retrieval{
		{Case: "ok", VMIdentifier: "did:example:a#key-1", Relationship: "authentication", Expect: []RetrievalExpectation{
			{Check: "returnsMethod", Value: want, Statements: []string{"s#1"}},
			{Check: "returnsIdentified", Statements: []string{"s#2"}, Partial: "p"},
		}},
		{Case: "err", VMIdentifier: "did:example:a#key-2", Expect: []RetrievalExpectation{
			{Check: "raisesError", Value: json.RawMessage(`"INVALID_VERIFICATION_METHOD"`), Statements: []string{"s#3"}},
		}},
		{Case: "unknown", VMIdentifier: "did:example:a#key-3", Expect: []RetrievalExpectation{{Check: "nope", Statements: []string{"s#4"}}}},
	}}
	if err := ValidateRetrievals(f); err == nil || !strings.Contains(err.Error(), "unknown check") {
		t.Fatalf("validate = %v", err)
	}
	bad := RetrievalFile{Scenarios: []Retrieval{{Expect: []RetrievalExpectation{{Check: "returnsMethod"}}}}}
	if err := ValidateRetrievals(bad); err == nil || !strings.Contains(err.Error(), "needs a value") || !strings.Contains(err.Error(), "names no statement") {
		t.Fatalf("validate bad = %v", err)
	}
	reg := &fixtures.Registry{Format: fixtures.Format, Method: fixtures.Method}
	cases := RetrievalCases("p", reg, f)
	if len(cases) != 3 || cases[0].ID != "p/retrieve-verification-method/ok" || cases[0].Needs[1] != core.CapVerificationMethodRetriever {
		t.Fatalf("cases = %+v", cases)
	}
	ctx := context.Background()
	ok := &retriever{res: core.RetrievalResult{VerificationMethod: method("did:example:a#key-1")}}
	if got := verdictList(cases[0].Run(ctx, ok)); got != "PASS,PASS" {
		t.Errorf("ok on success = %s", got)
	}
	if got := verdictList(cases[1].Run(ctx, ok)); got != "FAIL" {
		t.Errorf("err on success = %s", got)
	}
	if got := verdictList(cases[2].Run(ctx, ok)); got != "ERROR" {
		t.Errorf("unknown check = %s", got)
	}
	wrongID := &retriever{res: core.RetrievalResult{VerificationMethod: method("did:example:a#key-9")}}
	if got := verdictList(cases[0].Run(ctx, wrongID)); got != "FAIL,FAIL" {
		t.Errorf("ok on wrong id = %s", got)
	}
	raised := &retriever{res: core.RetrievalResult{Error: &core.ProcessingError{Type: "https://w3id.org/security#INVALID_VERIFICATION_METHOD", Detail: "d"}}}
	obs := cases[1].Run(ctx, raised)
	if verdictList(obs) != "PASS" || !strings.Contains(obs[0].Detail, "matches") {
		t.Errorf("err on error = %+v", obs)
	}
	other := &retriever{res: core.RetrievalResult{Error: &core.ProcessingError{Type: "x"}}}
	if obs := cases[1].Run(ctx, other); !strings.Contains(obs[0].Detail, "differs") {
		t.Errorf("other type = %+v", obs)
	}
	if obs := cases[0].Run(ctx, raised); verdictList(obs) != "FAIL,FAIL" || !strings.Contains(obs[0].Observed, "error") {
		t.Errorf("ok on error = %+v", obs)
	}
	if got := verdictList(cases[0].Run(ctx, &retriever{})); got != "FAIL,FAIL" {
		t.Errorf("ok on nothing = %s", got)
	}
	if obs := cases[1].Run(ctx, &retriever{}); obs[0].Observed != "neither a verification method nor an error" {
		t.Errorf("err on nothing = %+v", obs)
	}
	if got := verdictList(cases[0].Run(ctx, &retriever{err: errors.New("x")})); got != "ERROR,ERROR" {
		t.Errorf("call error = %s", got)
	}
	if got := verdictList(cases[0].Run(ctx, &retriever{loadErr: errors.New("x")})); got != "ERROR,ERROR" {
		t.Errorf("load error = %s", got)
	}
	if got := absoluteIn("not a did", "#k"); got != "#k" {
		t.Errorf("absoluteIn = %q", got)
	}
	if joinNotes("", "b") != "b" || joinNotes("a", "") != "a" || joinNotes("a", "b") != "a; b" {
		t.Error("joinNotes")
	}
}

func TestVMValidatorCases(t *testing.T) {
	vm := core.NewDocument(core.M("secretKeyMultibase", core.String("z1")))
	groups := []VMGroup{{Case: "g", Partial: "p", Vectors: []VMVector{
		{Name: "good", Method: vm, Property: "secretKeyMultibase", Valid: true, Statements: []string{"s#1"}},
		{Name: "bad", Method: vm, Property: "secretKeyMultibase", Why: "w", Statements: []string{"s#1", "s#2"}},
	}}}
	if err := ValidateVMGroups(groups); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVMGroups([]VMGroup{{Vectors: []VMVector{{Name: "x"}}}}); err == nil || !strings.Contains(err.Error(), "has no why") {
		t.Fatalf("invalid groups = %v", err)
	}
	cases := VMValidatorCases("p", "1.1", groups)
	if len(cases) != 1 || cases[0].ID != "p/verification-method/g" || len(cases[0].Statements) != 2 {
		t.Fatalf("cases = %+v", cases)
	}
	ctx := context.Background()
	if got := verdictList(cases[0].Run(ctx, &retriever{})); got != "PASS,FAIL,FAIL" {
		t.Errorf("silent = %s", got)
	}
	at := &retriever{findings: []core.Finding{{Code: "c", Path: "/secretKeyMultibase/x", Message: "m"}}}
	if got := verdictList(cases[0].Run(ctx, at)); got != "FAIL,PASS,PASS" {
		t.Errorf("finding at property = %s", got)
	}
	elsewhere := &retriever{findings: []core.Finding{{Code: "c", Path: "/publicKeyMultibase"}}}
	if got := verdictList(cases[0].Run(ctx, elsewhere)); got != "PASS,FAIL,FAIL" {
		t.Errorf("finding elsewhere = %s", got)
	}
	if got := verdictList(cases[0].Run(ctx, &retriever{valErr: errors.New("x")})); got != "ERROR,ERROR,ERROR" {
		t.Errorf("validator error = %s", got)
	}
}
