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

// fake is a scriptable subject for testing the kit itself.
type fake struct {
	loadErr   error
	parseErr  error
	parts     core.DIDParts
	urlParts  core.DIDURLParts
	consumeOK bool
	produced  []byte
	produceMT string
	findings  []core.Finding
	valErr    error
	res       core.ResolutionResult
	deref     core.DereferenceResult
	callErr   error
}

func (f *fake) Describe() core.SubjectInfo                   { return core.SubjectInfo{Name: "fake"} }
func (f *fake) Supports(string, core.Capability) bool        { return true }
func (f *fake) LoadFixtureRegistry(*fixtures.Registry) error { return f.loadErr }
func (f *fake) ParseDID(string) (core.DIDParts, error)       { return f.parts, f.parseErr }
func (f *fake) ParseDIDURL(string) (core.DIDURLParts, error) { return f.urlParts, f.parseErr }
func (f *fake) Validate(core.DocumentJSON, string) ([]core.Finding, error) {
	return f.findings, f.valErr
}
func (f *fake) Consume(data []byte, mt, _ string, _ bool) (core.DocumentJSON, core.ConsumeInfo, error) {
	if !f.consumeOK {
		return core.DocumentJSON{}, core.ConsumeInfo{}, errors.New("rejected")
	}
	d, _ := core.ParseDocumentJSON(data)
	return d, core.ConsumeInfo{MediaType: mt}, nil
}
func (f *fake) Produce(core.DocumentJSON, string) ([]byte, string, error) {
	if f.produced == nil {
		return nil, "", errors.New("refused")
	}
	return f.produced, f.produceMT, nil
}
func (f *fake) Resolve(context.Context, string, map[string]any) (core.ResolutionResult, error) {
	return f.res, f.callErr
}
func (f *fake) Resolve10(context.Context, string, map[string]any) (core.ResolutionResult, error) {
	return f.res, f.callErr
}
func (f *fake) ResolveRepresentation10(context.Context, string, map[string]any) (core.ResolutionResult, error) {
	return f.res, f.callErr
}
func (f *fake) Dereference(context.Context, string, map[string]any) (core.DereferenceResult, error) {
	return f.deref, f.callErr
}
func (f *fake) Dereference10(context.Context, string, map[string]any) (core.DereferenceResult, error) {
	return f.deref, f.callErr
}

var ctx = context.Background()

func doc(t *testing.T, s string) core.DocumentJSON {
	t.Helper()
	d, err := core.ParseDocumentJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func verdicts(obs []core.Observation) map[core.Verdict]int {
	out := map[core.Verdict]int{}
	for _, o := range obs {
		out[o.Verdict]++
	}
	return out
}

func TestRecorderAndUnion(t *testing.T) {
	var r Recorder
	r.Judge([]string{"a", "b"}, "in", true, "", "", "partly")
	r.Judge([]string{"a"}, "in", false, "x", "", "")
	r.All([]string{"c"}, core.NotApplicable, "in", "d")
	obs := r.Observations()
	if len(obs) != 4 || obs[0].Detail != "partly" || obs[2].Observed != "(nothing)" || obs[3].Verdict != core.NotApplicable {
		t.Fatalf("observations = %+v", obs)
	}
	if got := Union([]string{"a", "b"}, []string{"b", "c"}); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("Union = %v", got)
	}
}

func TestDecodeAndMust(t *testing.T) {
	var v struct{ A int }
	if err := Decode("x", []byte(`{"A":1}`), &v); err != nil || v.A != 1 {
		t.Fatalf("Decode = %v %v", v, err)
	}
	if err := Decode("x", []byte(`{"B":1}`), &v); err == nil {
		t.Error("unknown field accepted")
	}
	mustPanic(t, func() { MustDecode("x", []byte(`[`), &v) })
	mustPanic(t, func() { MustRegistry("x", []byte(`{}`)) })
	mustPanic(t, func() { MustDocument("[]") })
	if r := MustRegistry("x", []byte(`{"format":"did-inspector-fixture-registry/1","method":"example","entries":{}}`)); r == nil {
		t.Error("nil registry")
	}
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	f()
}

func TestRegistryCase(t *testing.T) {
	run := RegistryCase(&fixtures.Registry{}, []string{"s"}, func(context.Context, core.Subject) []core.Observation {
		return []core.Observation{{Statement: "s", Verdict: core.Pass}}
	})
	if obs := run(ctx, &fake{}); obs[0].Verdict != core.Pass {
		t.Errorf("loaded: %+v", obs)
	}
	if obs := run(ctx, &fake{loadErr: errors.New("no")}); obs[0].Verdict != core.Error || !strings.Contains(obs[0].Detail, "could not load") {
		t.Errorf("load failure: %+v", obs)
	}
}

func str(s string) *string { return &s }
func boolp(b bool) *bool   { return &b }

func TestSyntaxCases(t *testing.T) {
	f := SyntaxFile{Groups: []SyntaxGroup{
		{Case: "d", Kind: "did", Statements: []string{"s"}, Items: []SyntaxItem{
			{Input: "did:x:1", Valid: true, Method: str("x"), ID: str("1")},
			{Input: "bad", Valid: false, Why: "w"},
		}},
		{Case: "u", Kind: "did-url", Statements: []string{"s"}, Items: []SyntaxItem{
			{Input: "did:x:1#f", Valid: true, Fragment: str("f"), HasFragment: boolp(true), HasQuery: boolp(false)},
		}},
	}}
	cs := SyntaxCases("p", f)
	if len(cs) != 2 || cs[0].ID != "p/syntax/d" {
		t.Fatalf("cases = %+v", cs)
	}
	good := &fake{parts: core.DIDParts{Method: "x", MethodSpecificID: "1"}, urlParts: core.DIDURLParts{Fragment: "f", HasFragment: true}}
	// The fake accepts everything, so the invalid item fails.
	if v := verdicts(cs[0].Run(ctx, good)); v[core.Pass] != 1 || v[core.Fail] != 1 {
		t.Errorf("did verdicts = %v", v)
	}
	if v := verdicts(cs[1].Run(ctx, good)); v[core.Pass] != 1 {
		t.Errorf("did-url verdicts = %v", v)
	}
	wrong := &fake{parts: core.DIDParts{Method: "y"}}
	if v := verdicts(cs[0].Run(ctx, wrong)); v[core.Fail] != 2 {
		t.Errorf("wrong parts verdicts = %v", v)
	}
	rejecting := &fake{parseErr: errors.New("no")}
	if v := verdicts(cs[0].Run(ctx, rejecting)); v[core.Fail] != 1 || v[core.Pass] != 1 {
		t.Errorf("rejecting verdicts = %v", v)
	}
}

func docFile() DocFile {
	var f DocFile
	MustDecode("docs", []byte(`{"groups":[{"case":"g","note":"n","judges":{"consumer":["s"],"producer":["s"],"validator":["s"]},
	  "valid":[{"name":"v","document":{"id":"did:x:1"}}],
	  "invalid":[{"name":"i","why":"w","document":{"id":1}},{"name":"t","why":"w","text":"[1]","mediaType":"m"}]}]}`), &f)
	return f
}

func TestDocCases(t *testing.T) {
	cfg := DocConfig{Profile: "p", Version: "1.1", MediaType: func(DocFixture) string { return "application/did" },
		ConsumerErrors: []string{"ce"}, ProducerNonConforming: []string{"pn"}}
	cs := DocCases(cfg, docFile())
	if len(cs) != 3 || !strings.HasSuffix(cs[0].ID, "/consumer") || cs[0].Statements[1] != "ce" || cs[1].Statements[1] != "pn" {
		t.Fatalf("cases = %+v", cs)
	}
	accepting := &fake{consumeOK: true, produced: []byte(`{}`), produceMT: "m"}
	if v := verdicts(cs[0].Run(ctx, accepting)); v[core.Pass] != 1 || v[core.Fail] != 4 {
		t.Errorf("consumer verdicts = %v", v)
	}
	if v := verdicts(cs[0].Run(ctx, &fake{})); v[core.Fail] != 1 || v[core.Pass] != 4 {
		t.Errorf("rejecting consumer verdicts = %v", v)
	}
	if v := verdicts(cs[1].Run(ctx, accepting)); v[core.Pass] != 1 || v[core.Fail] != 2 {
		t.Errorf("producer verdicts = %v", v)
	}
	if v := verdicts(cs[1].Run(ctx, &fake{})); v[core.Fail] != 1 || v[core.Pass] != 2 {
		t.Errorf("refusing producer verdicts = %v", v)
	}
	if v := verdicts(cs[2].Run(ctx, &fake{})); v[core.Pass] != 1 || v[core.Fail] != 1 {
		t.Errorf("silent validator verdicts = %v", v)
	}
	if v := verdicts(cs[2].Run(ctx, &fake{findings: []core.Finding{{Code: "c"}}})); v[core.Pass] != 1 || v[core.Fail] != 1 {
		t.Errorf("noisy validator verdicts = %v", v)
	}
	if v := verdicts(cs[2].Run(ctx, &fake{valErr: errors.New("x")})); v[core.Error] != 2 {
		t.Errorf("failing validator verdicts = %v", v)
	}
	skip := docFile()
	skip.Groups[0].SkipGeneral = true
	if cs := DocCases(cfg, skip); len(cs[0].Statements) != 1 {
		t.Errorf("skipGeneral kept general statements: %v", cs[0].Statements)
	}
	mustPanic(t, func() { DocFixture{Document: core.Number("x")}.Bytes() })
	if _, ok := (DocFixture{Text: str("x")}).Doc(); ok {
		t.Error("text fixture has a document")
	}
}

func TestValidate(t *testing.T) {
	if err := ValidateDocs(docFile()); err != nil {
		t.Error(err)
	}
	bad := DocFile{Groups: []DocGroup{{Judges: map[string][]string{"x": nil, "producer": {"s"}}, Valid: []DocFixture{{Text: str("t")}}, Invalid: []DocFixture{{Name: "i", Text: str("t")}}}}}
	if err := ValidateDocs(bad); err == nil || strings.Count(err.Error(), "\n") < 4 {
		t.Errorf("ValidateDocs = %v", err)
	}
	if err := ValidateSyntax(SyntaxFile{Groups: []SyntaxGroup{{Kind: "x", Items: []SyntaxItem{{Input: "a"}}}}}); err == nil || strings.Count(err.Error(), "\n") < 2 {
		t.Errorf("ValidateSyntax = %v", err)
	}
	sc := ScenarioFile{Scenarios: []Scenario{{Function: "nope", Expect: []Expectation{{Check: "nope"}, {Check: "errorCode", Statements: []string{"s"}}}}},
		Probes: []Probe{{Function: "nope"}}}
	if err := ValidateScenarios(sc); err == nil || strings.Count(err.Error(), "\n") < 5 {
		t.Errorf("ValidateScenarios = %v", err)
	}
}

func TestCallAndOutcome(t *testing.T) {
	d := doc(t, `{"id":"did:x:1"}`)
	f := &fake{
		res:   core.ResolutionResult{ResolutionMetadata: doc(t, `{"contentType":"application/did"}`), Document: &d, DocumentMetadata: doc(t, `{"a":1}`)},
		deref: core.DereferenceResult{DereferencingMetadata: doc(t, `{"error":"notFound"}`)},
	}
	for _, fn := range []string{FnResolve, FnResolve10, FnResolveRepresentation10} {
		o := Call(ctx, f, fn, "did:x:1", nil)
		if !o.Succeeded() || o.Failed() || o.ErrorCode() != "" {
			t.Errorf("%s: %+v", fn, o)
		}
		if got, why := o.Doc(); why != "" || got.Len() != 1 {
			t.Errorf("%s: Doc = %v %s", fn, got, why)
		}
	}
	for _, fn := range []string{FnDereference, FnDereference10} {
		o := Call(ctx, f, fn, "did:x:1", nil)
		if o.Succeeded() || o.ErrorCode() != "notFound" || o.HasContent() {
			t.Errorf("%s: %+v", fn, o)
		}
		if _, why := o.Doc(); why == "" {
			t.Errorf("%s: Doc without content", fn)
		}
	}
	if o := Call(ctx, f, "nope", "x", nil); o.Err == nil || !strings.Contains(o.Summary(), "call failed") {
		t.Errorf("unknown function: %+v", o)
	}
	o := Outcome{Metadata: doc(t, `{"error":{"type":"T"}}`), Stream: []byte(strings.Repeat("x", 300))}
	if o.ErrorCode() != "T" || !strings.Contains(o.Summary(), "...") {
		t.Errorf("object error: %q %s", o.ErrorCode(), o.Summary())
	}
	if _, why := o.Doc(); !strings.Contains(why, "not a JSON object") {
		t.Errorf("Doc of a non-JSON stream: %s", why)
	}
	if (Outcome{Metadata: doc(t, `{"error":1}`)}).ErrorCode() != "" {
		t.Error("numeric error has a code")
	}
	if _, ok := FunctionCapability("nope"); ok {
		t.Error("unknown function has a capability")
	}
	if _, ok := StringMember(doc(t, `{"a":1}`), "a"); ok {
		t.Error("number read as string")
	}
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestChecks(t *testing.T) {
	d := doc(t, `{"@context":"c","id":"did:x:1","service":[{"id":"#s"},{"id":"did:x:1#t"}]}`)
	ok := Outcome{
		Input:           "did:x:1?service=s",
		Metadata:        doc(t, `{"contentType":"application/did; charset=utf-8"}`),
		Document:        &d,
		ContentMetadata: doc(t, `{"deactivated":true,"created":"x"}`),
	}
	bad := Outcome{
		Input:           "did:x:1",
		Metadata:        doc(t, `{"error":"notFound"}`),
		ContentMetadata: doc(t, `{"deactivated":"yes"}`),
		Stream:          []byte("not a uri\r\n"),
	}
	cases := []struct {
		check string
		value string
	}{
		{"success", ``}, {"noError", ``},
		{"documentId", `"did:x:1"`}, {"documentHas", `{"id":"did:x:1"}`},
		{"documentEquals", `{"id":"did:x:1","service":[{"id":"#s"},{"id":"did:x:1#t"}]}`},
		{"serviceIds", `["did:x:1#s","did:x:1#t"]`}, {"deactivated", `true`},
		{"contentMetadataHas", `{"created":"x"}`}, {"contentType", `"application/did"`},
		{"contentTypeAnywhere", `["application/did"]`}, {"successOrErrorCode", `"X"`},
		{"resourceEquals", `{"@context":"other","id":"#x","service":[{"id":"#s"},{"id":"did:x:1#t"}]}`},
	}
	for _, c := range cases {
		check := Checks[c.check]
		if c.check == "resourceEquals" {
			res := doc(t, `{"id":"did:x:1#x","service":[{"id":"#s"},{"id":"did:x:1#t"}]}`)
			o := ok
			o.Document = &res
			if pass, exp, obs := check(o, raw(c.value)); !pass {
				t.Errorf("%s on ok: %s / %s", c.check, exp, obs)
			}
		} else if pass, exp, obs := check(ok, raw(c.value)); !pass {
			t.Errorf("%s on ok: %s / %s", c.check, exp, obs)
		}
		if pass, _, _ := check(bad, raw(c.value)); pass {
			t.Errorf("%s passed on bad", c.check)
		}
	}
	for _, c := range []struct{ check, value string }{
		{"errorPresent", ``}, {"errorCode", `["notFound"]`}, {"metadataNotEmpty", ``},
		{"contentTypeAbsent", ``}, {"successOrErrorCode", `["notFound"]`},
	} {
		if pass, exp, obs := Checks[c.check](bad, raw(c.value)); !pass {
			t.Errorf("%s on bad: %s / %s", c.check, exp, obs)
		}
		if pass, _, _ := Checks[c.check](ok, raw(c.value)); pass && c.check != "successOrErrorCode" && c.check != "metadataNotEmpty" {
			t.Errorf("%s passed on ok", c.check)
		}
	}
	empty := Outcome{}
	if pass, _, _ := Checks["noContent"](empty, nil); !pass {
		t.Error("noContent on empty")
	}
	if pass, _, _ := Checks["metadataNotEmpty"](empty, nil); pass {
		t.Error("metadataNotEmpty on empty")
	}
	if pass, _, _ := Checks["contentMetadataEmpty"](empty, nil); !pass {
		t.Error("contentMetadataEmpty on empty")
	}
	if pass, _, _ := Checks["contentMetadataEmpty"](ok, nil); pass {
		t.Error("contentMetadataEmpty on ok")
	}
	list := Outcome{Stream: []byte("https://a.example/\r\n")}
	if pass, _, _ := Checks["uriList"](list, raw(`["https://a.example/"]`)); !pass {
		t.Error("uriList")
	}
	if pass, _, _ := Checks["uriList"](bad, raw(`[]`)); pass {
		t.Error("uriList on a bad list")
	}
	if pass, _, _ := Checks["streamIsJSONObject"](Outcome{Stream: []byte(`{}`)}, nil); !pass {
		t.Error("streamIsJSONObject")
	}
	for _, o := range []Outcome{empty, bad} {
		if pass, _, _ := Checks["streamIsJSONObject"](o, nil); pass {
			t.Error("streamIsJSONObject on no JSON")
		}
	}
	if pass, _, _ := Checks["deactivated"](Outcome{}, raw(`false`)); pass {
		t.Error("deactivated without the property")
	}
	if baseDID("bad") != "bad" {
		t.Error("baseDID of a non-DID URL")
	}
}

func TestJudgeScenario(t *testing.T) {
	sc := Scenario{Case: "c", Function: FnResolve, Input: "did:x:1", UnsupportedIf: []string{"FNS"}, NotApplicableIfSuccess: true,
		Expect: []Expectation{{Check: "errorCode", Value: raw(`"E"`), Statements: []string{"a"}}, {Check: "nope", Statements: []string{"b"}}}}
	d := doc(t, `{"id":"did:x:1"}`)
	cases := []struct {
		o    Outcome
		want core.Verdict
	}{
		{Outcome{Err: errors.New("x")}, core.Error},
		{Outcome{Metadata: doc(t, `{"error":"FNS"}`)}, core.NotSupported},
		{Outcome{Document: &d}, core.NotApplicable},
		{Outcome{Metadata: doc(t, `{"error":"E"}`)}, core.Pass},
		{Outcome{Metadata: doc(t, `{"error":"F"}`)}, core.Fail},
	}
	for _, c := range cases {
		obs := JudgeScenario(sc, c.o)
		if obs[0].Verdict != c.want {
			t.Errorf("%+v: %s, want %s", c.o, obs[0].Verdict, c.want)
		}
	}
	if obs := JudgeScenario(sc, Outcome{Metadata: doc(t, `{"error":"E"}`)}); obs[1].Verdict != core.Error {
		t.Errorf("unknown check: %+v", obs[1])
	}
	reg := &fixtures.Registry{}
	cs := ScenarioCases("p", "resolution", reg, ScenarioFile{Scenarios: []Scenario{sc}})
	if len(cs) != 1 || cs[0].ID != "p/resolution/c" || len(cs[0].Needs) != 2 {
		t.Fatalf("cases = %+v", cs)
	}
	if obs := cs[0].Run(ctx, &fake{res: core.ResolutionResult{ResolutionMetadata: doc(t, `{"error":"E"}`)}}); obs[0].Verdict != core.Pass {
		t.Errorf("run: %+v", obs)
	}
	if got := CloneOptions(map[string]any{"a": 1}); got["a"] != 1 {
		t.Error("CloneOptions")
	}
}

func TestInvariantCase(t *testing.T) {
	invs := []Invariant{
		MemberRule("created", "", PickContentMetadata, "created", "datetime", IsDatetime),
		MemberRule("ct", "", PickMetadata, "contentType", "ASCII", IsASCIIString),
		MethodRule("eq", "equivalentId", true),
		MethodRule("can", "canonicalId", false),
	}
	f := ScenarioFile{
		Scenarios: []Scenario{{Case: "c", Function: FnResolve, Input: "did:x:1"}},
		Probes:    []Probe{{Function: FnResolve, Input: "did:x:2"}},
	}
	c := InvariantCase("p/inv", "p", &fixtures.Registry{}, invs, f)
	good := &fake{res: core.ResolutionResult{DocumentMetadata: doc(t, `{"created":"2020-01-01T00:00:00Z","equivalentId":["did:x:a"],"canonicalId":"did:x:b"}`)}}
	v := verdicts(c.Run(ctx, good))
	if v[core.Pass] != 6 || v[core.NotApplicable] != 1 {
		t.Errorf("good verdicts = %v", v)
	}
	bad := &fake{res: core.ResolutionResult{DocumentMetadata: doc(t, `{"created":"2020","equivalentId":["did:y:a"],"canonicalId":"did:y:b"}`)}}
	if v := verdicts(c.Run(ctx, bad)); v[core.Fail] != 6 {
		t.Errorf("bad verdicts = %v", v)
	}
	if v := verdicts(c.Run(ctx, &fake{callErr: errors.New("x")})); v[core.NotApplicable] != 4 {
		t.Errorf("failing calls verdicts = %v", v)
	}
	if empty := InvariantCase("p/x", "p", nil, invs, ScenarioFile{}); empty.Needs[1] != "" {
		t.Errorf("needs = %v", empty.Needs)
	}
}

func TestPredicates(t *testing.T) {
	v := func(s string) core.Value { x, _ := core.ParseJSON([]byte(s)); return x }
	if !IsSetOf(v(`["did:x:1","did:x:2"]`), IsDIDString) || IsSetOf(v(`["did:x:1","did:x:1"]`), IsDIDString) ||
		IsSetOf(v(`[1]`), IsDIDString) || IsSetOf(v(`"did:x:1"`), IsDIDString) {
		t.Error("IsSetOf")
	}
	if !IsMap(v(`{}`)) || IsMap(v(`[]`)) || IsASCIIString(v(`"é"`)) || IsDatetime(v(`1`)) {
		t.Error("predicates")
	}
	if SameMethod(Outcome{Input: "bad"})(v(`"did:x:1"`)) {
		t.Error("SameMethod with an invalid input")
	}
}

func TestRepresentationHelpers(t *testing.T) {
	d := doc(t, `{"@context":["c","d"],"id":"did:x:1","a":[1]}`)
	f := &fake{produced: []byte(`{"id":"did:x:1","a":[2]}`), produceMT: "m", consumeOK: true}
	p := Produce(f, d, "1.1")
	out, ok := p.Doc()
	if !ok || p.MediaType != "m" {
		t.Fatalf("Produce = %+v", p)
	}
	if ok, _, _ := MembersKept(out, d, "@context"); ok {
		t.Error("changed member kept")
	}
	if ok, exp, _ := MembersKept(out, doc(t, `{"z":1}`)); ok || !strings.Contains(exp, "z") {
		t.Error("missing member kept")
	}
	if ok, _, _ := MembersKept(d, d); !ok {
		t.Error("same document")
	}
	if _, ok := (Produced{Root: core.Array()}).Doc(); ok {
		t.Error("array root is a document")
	}
	c := Consume(f, []byte(`{"id":"did:x:1"}`), "m", "1.1")
	if c.Err != nil || c.Info.MediaType != "m" {
		t.Errorf("Consume = %+v", c)
	}
	ctxVal, _ := d.Get("@context")
	if !ContextFirst(ctxVal, "c") || ContextFirst(ctxVal, "d") || !ContextFirst(core.String("c"), "c") || ContextFirst(core.Number("1"), "c") {
		t.Error("ContextFirst")
	}
	rules := []Rule{{Statements: []string{"s"}, Check: func() (bool, string, string) { return true, "", "" }}}
	if obs := RunRules("in", nil, rules); obs[0].Verdict != core.Pass {
		t.Errorf("RunRules = %+v", obs)
	}
	if obs := RunRules("in", errors.New("x"), rules); obs[0].Verdict != core.Fail || obs[0].Observed != "x" {
		t.Errorf("RunRules with an error = %+v", obs)
	}
}
