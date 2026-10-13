package sageresolution

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func branchFixture(branch string) Result {
	result := Result{Metadata: json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}}`), ContentMetadata: json.RawMessage(`{}`)}
	if branch == "missing" {
		result.Metadata = json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		result.Raw = []byte(`null`)
	}
	if branch == "deactivated" {
		result.Metadata = json.RawMessage(`{}`)
		result.ContentMetadata = json.RawMessage(`{"deactivated":true}`)
	}
	return result
}
func TestNativeBranchIndependentOutcomes(t *testing.T) {
	for _, branch := range []string{"missing", "deactivated", "unexpected"} {
		for _, obs := range judgeBranch(branchFixture(branch), branch, "unit") {
			if obs.Verdict != core.Pass || obs.Input != "unit" || obs.Observed == "" {
				t.Fatal(obs)
			}
		}
		for _, tc := range []struct {
			mutate func(*Result)
			want   []int
		}{
			{func(r *Result) { r.Metadata = json.RawMessage(`{"error":{"type":"https://example.org/wrong"}}`) }, []int{0, 1}},
			{func(r *Result) {
				r.HasContent = true
				r.ContentKind = "document"
				r.ReturnedID = "did:example:a"
				r.Snapshot = json.RawMessage(`{"id":"did:example:a"}`)
			}, []int{0, 2}},
			{func(r *Result) { r.ContentMetadata = json.RawMessage(`{"extra":true}`) }, []int{0, 3}},
		} {
			result := branchFixture(branch)
			tc.mutate(&result)
			obs := judgeBranch(result, branch, "unit")
			for i, o := range obs {
				want := core.Pass
				for _, index := range tc.want {
					if i == index {
						want = core.Fail
					}
				}
				if o.Verdict != want {
					t.Fatal(branch, i, o)
				}
			}
		}
		for _, mutate := range []func(*Result){func(r *Result) { r.Metadata = json.RawMessage(`null`) }, func(r *Result) { r.ContentMetadata = json.RawMessage(`{"a":1,"a":2}`) }, func(r *Result) { r.Exchange = &core.HTTPExchange{} }, func(r *Result) { r.Native = &NativeObservation{} }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) }} {
			result := branchFixture(branch)
			mutate(&result)
			for _, obs := range judgeBranch(result, branch, "unit") {
				if obs.Verdict != core.Error || obs.Input != "unit" {
					t.Fatal(obs)
				}
			}
		}
	}
	for _, raw := range []string{`{}`, `[]`, `{`} {
		result := branchFixture("missing")
		result.Raw = []byte(raw)
		obs := judgeBranch(result, "missing", "unit")
		if obs[2].Verdict != core.Fail || obs[1].Verdict != core.Pass || obs[3].Verdict != core.Pass {
			t.Fatal(obs)
		}
	}
}
