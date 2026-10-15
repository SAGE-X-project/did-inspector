package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
)

const itemExpansionID = "res10-crd20261001#resolving-algorithm.29"

type itemCondition struct {
	Path      []string `json:"path"`
	Original  string   `json:"original"`
	Expected  string   `json:"expected"`
	Observed  string   `json:"observed"`
	Qualifies bool     `json:"qualifies"`
}
type itemExpansionEvidence struct {
	Proof expansionSourceEvidence `json:"proof"`
	Items []itemCondition         `json:"items"`
	Error string                  `json:"analysis_error,omitempty"`
}

// This predicate covers the five literal fragment-only object ids, not all URI grammar.
func qualifyingExpansionItem(parent *core.Value) bool {
	if parent == nil || parent.Kind != core.KindObject {
		return false
	}
	id, ok := parent.Get("id")
	return ok && id.Kind == core.KindString && strings.HasPrefix(id.Str, "#") && len(id.Str) > 1
}
func expansionItemConditions(values []RoutingResult) ([]itemCondition, bool) {
	fs := expansionSourceFixtures()
	if len(values) != len(fs) {
		return nil, false
	}
	out := []itemCondition{}
	for i, f := range fs {
		original, e := core.ParseJSON(f.Document)
		want, e1 := core.ParseJSON(f.Expected)
		got, e2 := core.ParseJSON(values[i].DataModel)
		if e != nil || e1 != nil || e2 != nil {
			return nil, false
		}
		for _, path := range f.Paths {
			if len(path) == 0 || path[len(path)-1] != "id" {
				return nil, false
			}
			parent := expansionNode(&original, path[:len(path)-1])
			a, b, c := expansionNode(&original, path), expansionNode(&want, path), expansionNode(&got, path)
			if !qualifyingExpansionItem(parent) || a == nil || b == nil || c == nil || a.Kind != core.KindString || b.Kind != core.KindString || c.Kind != core.KindString || b.Str != "did:example:123"+a.Str {
				return nil, false
			}
			out = append(out, itemCondition{Path: path, Original: a.Str, Expected: b.Str, Observed: c.Str, Qualifies: true})
		}
	}
	return out, len(out) == 5
}
func expansionItemVerdict(items []itemCondition) core.Verdict {
	if len(items) != 5 {
		return core.Error
	}
	verdict := core.Pass
	for _, item := range items {
		if !item.Qualifies || item.Original == "" || item.Expected == item.Original {
			return core.Error
		}
		if item.Observed == item.Original {
			verdict = core.Fail
		} else if item.Observed != item.Expected {
			return core.Error
		}
	}
	return verdict
}
func judgeItemExpansion(ctx context.Context, proof expansionSourceEvidence, input string) []core.Observation {
	e := itemExpansionEvidence{Proof: proof, Items: []itemCondition{}}
	obs := libraryUnavailable([]string{itemExpansionID}, core.Error, "For each qualifying literal object id, independently check the object/string/relative-fragment condition and its unchanged actual result. Shared source/receipt validation binds the same consumer model, closed traversal helpers and relocated-root controls; earlier clause verdicts are not the item predicate. Five ordinary method/service extension objects are missed. This is the existing traversal finding, not a new repair cause. Full URI grammar, every representation, authority and physical step tracing are unestablished.", input, nil)
	checked := judgeExpansionSource(ctx, proof, input)
	if proof.Error != "" || json.Unmarshal([]byte(checked[0].Observed), &e.Proof) != nil || checked[0].Verdict == core.Error || checked[1].Verdict == core.Error {
		e.Error = "missing or contradictory same-call source/expansion premises"
	} else {
		var valid bool
		e.Items, valid = expansionItemConditions(proof.Runtime)
		if valid {
			obs[0].Verdict = expansionItemVerdict(e.Items)
		} else {
			e.Error = "missing independently qualifying object ids"
		}
	}
	raw, _ := json.Marshal(e)
	obs[0].Observed = string(raw)
	obs[0].Expected = "All five preserved object ids satisfy the relative-id condition and must be processed, including method/service extension maps"
	return obs
}
func appendItemExpansionCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/item-expansion-conditions", Profile: p.Name, Statements: []string{itemExpansionID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		q := expansionSourceRequest()
		input, _ := json.Marshal(q)
		if !ok || !ok1 {
			return libraryUnavailable([]string{itemExpansionID}, core.NotSupported, "no selected source/routing operations", string(input), nil)
		}
		e := expansionSourceEvidence{Runtime: []RoutingResult{}}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return libraryUnavailable([]string{itemExpansionID}, core.Error, err.Error(), string(input), e)
		}
		for _, f := range expansionSourceFixtures() {
			v, err := routing.InspectRouting(ctx, expansionSourceRouting(f))
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return libraryUnavailable([]string{itemExpansionID}, core.Error, err.Error(), string(input), e)
			}
		}
		return judgeItemExpansion(ctx, e, string(input))
	}})
}
