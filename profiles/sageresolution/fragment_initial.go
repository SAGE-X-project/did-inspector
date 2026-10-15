package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

type fragmentInitialEvidence struct {
	Source  fragmentSourceEvidence           `json:"source_evidence"`
	Initial sourcearith.FragmentInitialAudit `json:"initial"`
}

func fragmentInitialVerdict(a sourcearith.FragmentInitialAudit) core.Verdict {
	if fragmentSourceVerdict(a.Binding, 2) != core.Pass || len(a.Unknown) != 0 || a.Search != IntegerSourceModule+"/dereferencer.findFragment" || a.LanguageRule != "https://go.dev/ref/spec#Return_statements; function-entry result values have their type's zero value" || !reflect.DeepEqual(a.ResultTypes, []string{"any", "bool"}) || !reflect.DeepEqual(a.ResultRoles, []string{"found", "ok"}) || !reflect.DeepEqual(a.InitialValues, []string{"nil interface (no fragment)", "false (no match)"}) {
		return core.Error
	}
	return core.Pass
}

func judgeFragmentInitial(ctx context.Context, e fragmentSourceEvidence, input string) []core.Observation {
	const id = "cid10#fragment-resolution.1"
	// Reuse the existing immutable source capture and independent provenance
	// checks. Their final payload is corroboration, never the initial-state oracle.
	prior := judgeFragmentSource(ctx, e, input)
	var checked fragmentSourceEvidence
	obs := libraryUnavailable([]string{id}, core.Error, "Selected fixed-source search-entry phase: Go language semantics initialize the actual unnamed (any,bool) result pair to (nil,false). Typed caller locals and the reviewed search/getter/caller envelope bind that pair to an initially absent fragment. Stable normal typed document and side-effect-free identifier preparation only. Not an explicit documentFragment local, runtime trace, complete alternative-output equivalence or every-map traversal. Final null alone is insufficient.", input, e)
	if len(prior) != 3 || json.Unmarshal([]byte(prior[0].Observed), &checked) != nil || checked.Error != "" || fragmentSourceVerdict(checked.Audit, 2) == core.Error || fragmentRuntime(checked.Runtime) != core.Pass {
		return obs
	}
	program := sourcearith.NewProgram(ctx, IntegerSourceModule, checked.Source.Files)
	if _, err := program.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		return obs
	}
	initial := program.FragmentInitialAudit(IntegerSourceModule + "/dereferencer.resolveFragment")
	evidence := fragmentInitialEvidence{Source: checked, Initial: initial}
	raw, _ := json.Marshal(evidence)
	obs[0].Observed = string(raw)
	if ctx.Err() != nil {
		return obs
	}
	obs[0].Verdict = fragmentInitialVerdict(initial)
	obs[0].Expected = "Actual unnamed search result slots start as nil/false under the explicitly trusted Go initialization rule; caller receives those same result roles"
	return obs
}

func appendFragmentInitialCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/fragment-initial-source", Profile: p.Name, Statements: []string{"cid10#fragment-resolution.1"}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		e := fragmentSourceEvidence{Compiler: runtime.Version(), Architecture: runtime.GOARCH, Runtime: [][]RoutingResult{}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		if !ok || !ok1 {
			return libraryUnavailable([]string{"cid10#fragment-resolution.1"}, core.NotSupported, "no source and routing observers", string(input), e)
		}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return libraryUnavailable([]string{"cid10#fragment-resolution.1"}, core.Error, err.Error(), string(input), e)
		}
		for _, f := range fragmentFixtures() {
			values := []RoutingResult{}
			for i := range f.Requests {
				v, err := routing.InspectRouting(ctx, resourceChoiceRequest(f, i))
				values = append(values, v)
				if err != nil {
					e.Runtime = append(e.Runtime, values)
					return libraryUnavailable([]string{"cid10#fragment-resolution.1"}, core.Error, err.Error(), string(input), e)
				}
			}
			e.Runtime = append(e.Runtime, values)
		}
		return judgeFragmentInitial(ctx, e, string(input))
	}})
}
