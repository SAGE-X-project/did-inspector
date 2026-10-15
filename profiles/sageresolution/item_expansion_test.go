package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func TestItemConditionsAndIndependentVerdict(t *testing.T) {
	e := expansionSourceControls(t)
	items, ok := expansionItemConditions(e.Runtime)
	if !ok || len(items) != 5 || expansionItemVerdict(items) != core.Fail {
		t.Fatal(items)
	}
	for i := range items {
		items[i].Observed = items[i].Expected
	}
	if expansionItemVerdict(items) != core.Pass {
		t.Fatal("positive literal oracle")
	}
	for _, change := range []func(*itemCondition){func(v *itemCondition) { v.Observed = "other" }, func(v *itemCondition) { v.Qualifies = false }, func(v *itemCondition) { v.Original = "" }, func(v *itemCondition) { v.Expected = v.Original }} {
		a := append([]itemCondition(nil), items...)
		change(&a[0])
		if expansionItemVerdict(a) != core.Error {
			t.Fatal(a)
		}
	}
	if expansionItemVerdict(nil) != core.Error {
		t.Fatal("missing")
	}
	for _, text := range []string{`null`, `[]`, `{}`, `{"id":true}`, `{"id":"#"}`, `{"id":"did:example:123#one"}`} {
		v, _ := core.ParseJSON([]byte(text))
		if qualifyingExpansionItem(&v) {
			t.Fatal(text)
		}
	}
	if qualifyingExpansionItem(nil) {
		t.Fatal("nil")
	}
	if _, ok := expansionItemConditions(nil); ok {
		t.Fatal("missing")
	}
	for _, value := range []string{`{`, `{}`, `{"id":3}`} {
		a := expansionSourceControls(t)
		a.Runtime[2].DataModel = []byte(value)
		if _, ok := expansionItemConditions(a.Runtime); ok {
			t.Fatal(value)
		}
	}
	original := append([]byte(nil), expansionSourceBytes...)
	defer func() { expansionSourceBytes = original }()
	for _, change := range []func([]expansionSourceFixture){func(f []expansionSourceFixture) { f[2].Paths[0] = nil }, func(f []expansionSourceFixture) { f[2].Paths[0] = []string{"other"} }, func(f []expansionSourceFixture) { f[2].Paths = nil }, func(f []expansionSourceFixture) { f[2].Document = []byte(`{`) }, func(f []expansionSourceFixture) { f[2].Expected = []byte(`{`) }, func(f []expansionSourceFixture) {
		var v map[string]any
		_ = json.Unmarshal(f[2].Expected, &v)
		v["verificationMethod"] = []any{}
		f[2].Expected, _ = json.Marshal(v)
	}} {
		expansionSourceBytes = original
		fs := expansionSourceFixtures()
		change(fs)
		expansionSourceBytes, _ = json.Marshal(fs)
		if _, ok := expansionItemConditions(e.Runtime); ok {
			t.Fatal("bad fixture")
		}
	}
}
func TestItemCaseSourceReceiptsAndAPI(t *testing.T) {
	e := expansionSourceControls(t)
	o := judgeItemExpansion(t.Context(), e, "unit")
	if len(o) != 1 || o[0].Verdict != core.Fail {
		t.Fatal(o)
	}
	var evidence itemExpansionEvidence
	if json.Unmarshal([]byte(o[0].Observed), &evidence) != nil || len(evidence.Items) != 5 || len(evidence.Proof.Audit.Frames) != 315 {
		t.Fatal("proof")
	}
	for _, change := range []func(*expansionSourceEvidence){func(e *expansionSourceEvidence) { e.Source.Files = nil }, func(e *expansionSourceEvidence) { e.Runtime = nil }, func(e *expansionSourceEvidence) { e.Error = "lost" }} {
		a := expansionSourceControls(t)
		change(&a)
		if judgeItemExpansion(t.Context(), a, "unit")[0].Verdict != core.Error {
			t.Fatal("missing")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeItemExpansion(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
	p := core.Profile{Name: "did-core-1.0"}
	appendItemExpansionCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("scope")
	}
	p.Name = "did-1.1"
	appendItemExpansionCase(&p)
	if p.Cases[0].Run(t.Context(), noOperation{})[0].Verdict != core.NotSupported {
		t.Fatal("unsupported")
	}
	for _, tc := range []struct {
		s    expansionSourceMock
		want core.Verdict
	}{{expansionSourceMock{e: e}, core.Fail}, {expansionSourceMock{e: e, failSource: true}, core.Error}, {expansionSourceMock{e: e, failRouting: true}, core.Error}} {
		if got := p.Cases[0].Run(t.Context(), tc.s)[0].Verdict; got != tc.want {
			t.Fatal(got)
		}
	}
}
