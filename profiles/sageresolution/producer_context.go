package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

const producerConformanceStatement = "did11-cr20260305#production-and-consumption.12"

type producerContextFixture struct {
	Name     string                 `json:"name"`
	Positive TypedProductionRequest `json:"positive"`
	Negative TypedProductionRequest `json:"negative"`
}
type producerContextPair struct {
	Positive TypedProductionResult `json:"positive"`
	Negative TypedProductionResult `json:"negative"`
}

func producerContextFixtures() []producerContextFixture {
	q := TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, Entries: []TypedMember{{Name: "@context", Value: TypedValue{Kind: "string", Text: did11Context}}}, JSONLD: true}
	bad := []TypedValue{{Kind: "boolean"}, {Kind: "integer", Text: "42"}, {Kind: "list", Items: []TypedValue{{Kind: "string", Text: did11Context}, {Kind: "boolean"}}}}
	rows := []producerContextFixture{}
	for i, v := range bad {
		negative := q
		negative.Entries = []TypedMember{{Name: "@context", Value: v}}
		rows = append(rows, producerContextFixture{Name: fmt.Sprintf("invalid-context-%d", i), Positive: q, Negative: negative})
	}
	return rows
}
func knownProducerContext(f producerContextFixture) bool {
	for _, x := range producerContextFixtures() {
		if reflect.DeepEqual(f, x) {
			return true
		}
	}
	return false
}

// attributedContextInput requires a built model and exactly one actual producer
// call. Builder rejection and errors annotated by the subject are not oracles.
func attributedContextInput(out TypedProductionResult, q TypedProductionRequest) bool {
	if out.BuildError != "" || out.CaptureError != "" || len(out.Calls) != 1 || out.ID != q.ID || out.ControllerShape != "set" || !reflect.DeepEqual(out.Controllers, q.Controllers) || !typedMembersEqual(out.Fields, q.Fields) || !typedMembersEqual(out.Entries, q.Entries) {
		return false
	}
	call := out.Calls[0]
	if call.Operation != pipelineProducer || call.Version != "1.1" || !call.JSONLD || call.IncludeSecret || call.CaptureError != "" {
		return false
	}
	model, e := parse(call.Model)
	entries, f := parse(call.Entries)
	wm, g := typedExpected(q, false, false)
	we, h := typedMap(q.Entries, false)
	return e == nil && f == nil && g == nil && h == nil && typedOutputEqual(model.Value(), wm) && typedOutputEqual(entries.Value(), we)
}

// contextOutput judges only the reviewed minimal public document and context.
// A base-only array is as valid as the base string. Richer context semantics
// require another observer and are not rejected merely for being unfamiliar.
func contextOutput(call ProductionCapture, q TypedProductionRequest) core.Verdict {
	if call.Error != "" || len(call.Output) == 0 {
		return core.Error
	}
	if !pipelineMedia(call.MediaType) {
		return core.NotSupported
	}
	value, e := core.ParseJSON(call.Output)
	if e != nil || value.Kind != core.KindObject || len(checks.DuplicateMembers(value)) > 0 {
		return core.Fail
	}
	ctx, present := value.Get("@context")
	if !present {
		return core.Fail
	}
	switch ctx.Kind {
	case core.KindString:
		if ctx.Str != did11Context {
			return core.Fail
		}
	case core.KindArray:
		if len(ctx.Array) == 0 || ctx.Array[0].Kind != core.KindString || ctx.Array[0].Str != did11Context {
			return core.Fail
		}
		for _, item := range ctx.Array[1:] {
			if item.Kind == core.KindBool {
				return core.Fail
			}
			if item.Kind != core.KindString && item.Kind != core.KindObject {
				return core.NotSupported
			}
		}
		if len(ctx.Array) > 1 {
			return core.NotSupported
		}
	default:
		return core.Fail
	}
	if len(value.Object) != 3 {
		return core.NotSupported
	}
	for i := range value.Object {
		if value.Object[i].Name == "@context" {
			value.Object[i].Value = core.String(did11Context)
		}
	}
	expected, e := typedExpected(TypedProductionRequest{ID: q.ID, Controllers: q.Controllers, JSONLD: true}, true, true)
	if e != nil {
		return core.Error
	}
	if !typedOutputEqual(value, expected) {
		return core.NotSupported
	}
	return core.Pass
}
func judgeProducerContext(out producerContextPair, f producerContextFixture, input string) core.Observation {
	raw, _ := json.Marshal(out)
	obs := core.Observation{Statement: producerConformanceStatement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "The selected producer does not return a successful non-conforming JSON-LD context for the reviewed public inputs", Detail: "Fresh accepted control and one-context-value negative pair. Scalar Boolean/Integer and a Boolean list suffix violate pinned DID JSON-LD context shape; the suffix basis is json-ld-processors.1 and its context definition, not .4 alone. Actual built model, typed pre-input, two maps, options, producer errors and bytes are archived. Refusal with no output and independently checked base-only repaired output are supported. Error plus partial bytes or silent no-output is ERROR. Richer output/context semantics are NOT_SUPPORTED, not automatically FAIL. This proves neither all invalid DID/document rejection nor full JSON-LD processing, authority, resolver ingress or downstream publication behavior."}
	if !knownProducerContext(f) || !attributedContextInput(out.Positive, f.Positive) || !attributedContextInput(out.Negative, f.Negative) {
		return obs
	}
	if contextOutput(out.Positive.Calls[0], f.Positive) != core.Pass {
		return obs
	}
	call := out.Negative.Calls[0]
	if call.Error != "" {
		if len(call.Output) == 0 {
			obs.Verdict = core.Pass
		}
		return obs
	}
	obs.Verdict = contextOutput(call, f.Negative)
	return obs
}
func appendProducerContextCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range producerContextFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-producer-context-" + f.Name, Profile: p.Name, Statements: []string{producerConformanceStatement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			obs := core.Observation{Statement: producerConformanceStatement, Input: string(input), Verdict: core.NotSupported, Detail: "no actual paired producer call"}
			s, ok := target.(TypedProductionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			positive, e := s.InspectTypedProduction(ctx, f.Positive)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			negative, e := s.InspectTypedProduction(ctx, f.Negative)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeProducerContext(producerContextPair{positive, negative}, f, string(input))}
		}})
	}
}
