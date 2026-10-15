package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func fragmentSearchControls(f fragmentSearchFixture) []RoutingResult {
	out := []RoutingResult{}
	for i := 0; i < 3; i++ {
		q := fragmentSearchRequest(f, i)
		r := resourceChoiceFixture{Document: q.Document.Data, Requests: []Request{q.Request, q.Request}, Content: f.Content, Kind: "map", ID: "did:example:resources#target", Media: "application/ld+json"}
		index := 0
		if i == 2 {
			index = 1
		}
		v := resourceControl(r, index)
		v.DataModel = q.Document.Data
		v.Entries = []byte(`{}`)
		out = append(out, v)
	}
	return out
}

func TestFragmentRecursiveSearchAndPremises(t *testing.T) {
	fixtures := fragmentSearchFixtures()
	if len(fixtures) != 5 {
		t.Fatal(fixtures)
	}
	for _, f := range fixtures {
		good := fragmentSearchControls(f)
		if o := judgeFragmentSearch(f, good, "unit")[0]; o.Verdict != core.Pass {
			t.Fatal(f.Name, o)
		}
		if judgeFragmentSearch(f, nil, "unit")[0].Verdict != core.Error {
			t.Fatal("missing calls")
		}
		other := f
		other.Name = "unknown"
		if judgeFragmentSearch(other, good, "unit")[0].Verdict != core.Error {
			t.Fatal("unknown fixture")
		}
		bad := fragmentSearchControls(f)
		bad[0].Result = bad[2].Result
		if o := judgeFragmentSearch(f, bad, "unit")[0]; o.Verdict != core.Fail {
			t.Fatal("preserved nested map not found", o)
		}
		for _, change := range []func(*RoutingResult){
			func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.Request.Request.Input = "other" }, func(v *RoutingResult) { v.DataModel = nil }, func(v *RoutingResult) { v.DataModel = []byte(`{}`) }, func(v *RoutingResult) { v.DataModel = []byte(`{`) }, func(v *RoutingResult) { v.Entries = nil }, func(v *RoutingResult) { v.Entries = []byte(`{"lost":1}`) }, func(v *RoutingResult) { v.ResolveOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.ContentMetadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`{`) }, func(v *RoutingResult) { v.Result.HasContent = false },
		} {
			v := fragmentSearchControls(f)
			change(&v[0])
			if o := judgeFragmentSearch(f, v, "unit")[0]; o.Verdict != core.Error {
				t.Fatal("unbound evidence", o)
			}
		}
		v := fragmentSearchControls(f)
		v[1].Result = v[2].Result
		if judgeFragmentSearch(f, v, "unit")[0].Verdict != core.Error {
			t.Fatal("universal refusal")
		}
		v = fragmentSearchControls(f)
		v[2].Result = v[1].Result
		if judgeFragmentSearch(f, v, "unit")[0].Verdict != core.Error {
			t.Fatal("wrong miss control")
		}
		v = fragmentSearchControls(f)
		v[2].Result.Metadata = []byte(`{"error":false}`)
		if judgeFragmentSearch(f, v, "unit")[0].Verdict != core.Error {
			t.Fatal("malformed problem")
		}
		v = fragmentSearchControls(f)
		v[0].Result.Raw = []byte(`{"id":"did:example:resources#other"}`)
		if judgeFragmentSearch(f, v, "unit")[0].Verdict != core.Error {
			t.Fatal("wrong map not attributed to recursion")
		}
	}
	v, _ := core.ParseJSON([]byte(`{"a":[false,{"id":"#x"},{"id":"did:example:resources#x","a":{"id":"#x"}}]}`))
	if len(fragmentMatches(v, "did:example:resources#x", "#x")) != 3 {
		t.Fatal("every map, array and relative id")
	}
	f := fixtures[0]
	f.Content = []byte(`{`)
	if judgeFragmentSearch(f, fragmentSearchControls(fixtures[0]), "unit")[0].Verdict != core.Error {
		t.Fatal("unreviewed fixture")
	}
}

type searchSubject struct {
	core.Subject
	err   bool
	calls int
}

func (s *searchSubject) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	s.calls++
	if s.err {
		return RoutingResult{}, errors.New("capture unavailable")
	}
	for _, f := range fragmentSearchFixtures() {
		for i := 0; i < 3; i++ {
			want := fragmentSearchRequest(f, i)
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(q)
			if string(a) == string(b) {
				return fragmentSearchControls(f)[i], nil
			}
		}
	}
	return RoutingResult{}, errors.New("unknown request")
}
func TestFragmentSearchCaseObservers(t *testing.T) {
	p := core.Profile{Name: "did-1.1"}
	appendFragmentSearchCases(&p)
	if len(p.Cases) != 5 {
		t.Fatal(p)
	}
	for _, c := range p.Cases {
		s := &searchSubject{}
		if c.Run(t.Context(), s)[0].Verdict != core.Pass || s.calls != 3 {
			t.Fatal(c.ID)
		}
		if c.Run(t.Context(), &searchSubject{err: true})[0].Verdict != core.Error {
			t.Fatal("error")
		}
		if c.Run(t.Context(), nil)[0].Verdict != core.NotSupported {
			t.Fatal("unsupported")
		}
	}
	old := core.Profile{Name: "did-core-1.0"}
	appendFragmentSearchCases(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
}

func TestFragmentSearchPayloadParsing(t *testing.T) {
	f := fragmentSearchFixtures()[0]
	want, _ := core.ParseJSON(f.Content)
	for _, change := range []func(*RoutingResult){func(v *RoutingResult) { v.Result.Raw = []byte(`{`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.ContentMetadata = []byte(`{`) }} {
		v := fragmentSearchControls(f)[0]
		change(&v)
		if fragmentMatchedContent(v, want) {
			t.Fatal("malformed payload")
		}
	}
}
