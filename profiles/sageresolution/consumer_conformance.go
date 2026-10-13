package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

var consumerConformanceStatements = []string{"did11-cr20260305#production-and-consumption.18", "cid10#conformance.2"}

// Fixtures contain only public material and a single named field violation.
// A paired accepted control is not proof of every rule for a complete document.
const conformanceControl = `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}],"authentication":["did:sage:web:registry.example:agent-1#sign"],"service":[{"id":"did:sage:web:registry.example:agent-1#a2a","type":"ExampleService","serviceEndpoint":"https://agent.example/service"}]}`

type conformanceFixture struct {
	Name      string             `json:"name"`
	Parent    string             `json:"parent"`
	Field     string             `json:"field"`
	Rule      string             `json:"rule"`
	Violation string             `json:"violated_statement"`
	Positive  ConsumptionRequest `json:"positive"`
	Negative  ConsumptionRequest `json:"negative"`
}
type consumerPair struct {
	Positive ConsumptionCapture `json:"positive"`
	Negative ConsumptionCapture `json:"negative"`
}

func conformanceDescriptors() []conformanceFixture {
	return []conformanceFixture{
		{Name: "missing-id", Field: "id", Rule: "missing", Violation: "cid10#subjects.2"},
		{Name: "nonstring-id", Field: "id", Rule: "nonstring", Violation: "cid10#subjects.1"},
		{Name: "missing-method-type", Parent: "verificationMethod", Field: "type", Rule: "missing", Violation: "cid10#verification-methods.3"},
		{Name: "missing-method-controller", Parent: "verificationMethod", Field: "controller", Rule: "missing", Violation: "cid10#verification-methods.3"},
		{Name: "nonstring-method-id", Parent: "verificationMethod", Field: "id", Rule: "nonstring", Violation: "cid10#verification-methods.5"},
		{Name: "nonstring-method-controller", Parent: "verificationMethod", Field: "controller", Rule: "nonstring", Violation: "cid10#verification-methods.7"},
		{Name: "missing-service-type", Parent: "service", Field: "type", Rule: "missing", Violation: "cid10#services.8"},
		{Name: "missing-service-endpoint", Parent: "service", Field: "serviceEndpoint", Rule: "missing", Violation: "cid10#services.11"},
		{Name: "empty-authentication", Field: "authentication", Rule: "empty-set", Violation: "cid10#authentication.2"},
	}
}
func fixtureMap(doc core.Value, f conformanceFixture) (core.Value, bool) {
	if f.Parent == "" {
		return doc, doc.Kind == core.KindObject
	}
	value, ok := doc.Get(f.Parent)
	if !ok || value.Kind != core.KindArray || len(value.Array) != 1 || value.Array[0].Kind != core.KindObject {
		return core.Value{}, false
	}
	return value.Array[0], true
}

// replaceFixtureField copies the maps/array it touches. An absent replacement
// strips just the controlled field for an independent one-field delta check.
func replaceFixtureField(doc core.Value, f conformanceFixture, replacement *core.Value) (core.Value, error) {
	target, ok := fixtureMap(doc, f)
	if !ok {
		return core.Value{}, fmt.Errorf("missing controlled fixture map")
	}
	members := []core.Member{}
	for _, member := range target.Object {
		if member.Name != f.Field {
			members = append(members, member)
		}
	}
	if replacement != nil {
		members = append(members, core.M(f.Field, *replacement))
	}
	changed := core.Object(members...)
	if f.Parent == "" {
		return changed, nil
	}
	root := append([]core.Member{}, doc.Object...)
	for i, member := range root {
		if member.Name == f.Parent {
			root[i].Value = core.Array(changed)
		}
	}
	return core.Object(root...), nil
}
func conformanceFixtures() ([]conformanceFixture, error) {
	doc, err := core.ParseJSON([]byte(conformanceControl))
	if err != nil {
		return nil, err
	}
	rows := conformanceDescriptors()
	for i, f := range rows {
		var replacement *core.Value
		if f.Rule == "nonstring" {
			value := core.Number("42")
			replacement = &value
		}
		if f.Rule == "empty-set" {
			value := core.Array()
			replacement = &value
		}
		bad, err := replaceFixtureField(doc, f, replacement)
		if err != nil {
			return nil, err
		}
		data, err := bad.MarshalJSON()
		if err != nil {
			return nil, err
		}
		rows[i].Positive = ConsumptionRequest{Data: []byte(conformanceControl), MediaType: "application/did"}
		rows[i].Negative = ConsumptionRequest{Data: data, MediaType: "application/did"}
	}
	return rows, nil
}
func controlledViolation(doc core.Value, f conformanceFixture) (bool, error) {
	target, ok := fixtureMap(doc, f)
	if !ok {
		return false, fmt.Errorf("fixture map unavailable")
	}
	value, present := target.Get(f.Field)
	switch f.Rule {
	case "missing":
		return !present, nil
	case "nonstring":
		return present && value.Kind != core.KindString, nil
	case "empty-set":
		return present && value.Kind == core.KindArray && len(value.Array) == 0, nil
	}
	return false, fmt.Errorf("unknown controlled fixture rule")
}
func sameConsumerCall(c ConsumptionCapture, q ConsumptionRequest) bool {
	return c.Operation == pipelineConsumer && string(c.Input) == string(q.Data) && c.MediaType == q.MediaType && q.MediaType == "application/did" && c.Require == "unknown" && c.Expected == "unknown" && !c.Strict
}
func knownConformanceDescriptor(f conformanceFixture) bool {
	for _, known := range conformanceDescriptors() {
		if f.Name == known.Name && f.Parent == known.Parent && f.Field == known.Field && f.Rule == known.Rule && f.Violation == known.Violation {
			return true
		}
	}
	return false
}

func judgeConsumerConformance(pair consumerPair, f conformanceFixture, input string) []core.Observation {
	raw, _ := json.Marshal(pair)
	verdict, detail := core.Error, "unavailable actual controlled consumer pair"
	positive, e1 := parse(f.Positive.Data)
	negative, e2 := parse(f.Negative.Data)
	control, _ := parse([]byte(conformanceControl))
	controlFixture, _ := checks.EqualJSON(positive.Value(), control.Value())
	if e1 == nil && e2 == nil && knownConformanceDescriptor(f) && controlFixture {
		violation, ev := controlledViolation(negative.Value(), f)
		controlBad, ec := controlledViolation(positive.Value(), f)
		left, el := replaceFixtureField(positive.Value(), f, nil)
		right, er := replaceFixtureField(negative.Value(), f, nil)
		equal, _ := checks.EqualJSON(left, right)
		if ev == nil && ec == nil && el == nil && er == nil && violation && !controlBad && equal && sameConsumerCall(pair.Positive, f.Positive) && sameConsumerCall(pair.Negative, f.Negative) {
			p, n := pair.Positive, pair.Negative
			model, em := parse(p.Model)
			entries, ee := parse(p.Entries)
			controlSame, _ := checks.EqualJSON(model.Value(), positive.Value())
			if p.Error == "" && p.CaptureError == "" && p.Version == "1.1" && !p.JSONLD && len(p.DroppedTerms) == 0 && em == nil && ee == nil && len(entries.Members) == 0 && controlSame {
				verdict = core.Fail
				if n.Error != "" && len(n.Model) == 0 && len(n.Entries) == 0 {
					verdict = core.Pass
				}
				detail = "Actual paired selected-consumer calls: accepted control plus one independently specified field violation (" + f.Violation + "). No subject validator verdict or error-reason code is an oracle. Only selected field rejection is established, not every schema rule, all nonconforming documents, key safety, authority, SAGE resolver/ingress or whole conformance. Errors and original bytes are retained."
			} else {
				detail = "paired control was not accepted and preserved; unconditional rejection cannot earn PASS"
			}
		}
	}
	out := []core.Observation{}
	for _, id := range consumerConformanceStatements {
		out = append(out, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Selected independently nonconforming object returns an actual consumer error and no document after a paired accepted control", Observed: string(raw), Detail: detail})
	}
	return out
}
func appendConsumerConformanceCases(p *core.Profile) error {
	if p.Name != "did-1.1" {
		return nil
	}
	fixtures, err := conformanceFixtures()
	if err != nil {
		return err
	}
	for _, f := range fixtures {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-consumer-conformance-" + f.Name, Profile: p.Name, Statements: append([]string{}, consumerConformanceStatements...), Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			missing := func(v core.Verdict, detail string) []core.Observation {
				out := unavailable(consumerConformanceStatements, v, detail)
				for i := range out {
					out[i].Input = string(input)
				}
				return out
			}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return missing(core.NotSupported, "no selected consumer input operation")
			}
			positive, e := s.InspectConsumption(ctx, f.Positive)
			if e != nil {
				return missing(core.Error, e.Error())
			}
			negative, e := s.InspectConsumption(ctx, f.Negative)
			if e != nil {
				return missing(core.Error, e.Error())
			}
			return judgeConsumerConformance(consumerPair{positive, negative}, f, string(input))
		}})
	}
	return nil
}
