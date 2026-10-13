package sageresolution

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

// Downloaded independently from W3C /ns/did-vocab/v1.1rc1.jsonld. Its exact
// hash is the pinned publication's remote-resource-integrity.1 digest.
//
//go:embed did-v1.1-context.jsonld
var independentDIDContext []byte

const contextDigest = "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85"
const unusedTerm = "inspectionNote"

func contextOracleReady() bool {
	sum := sha256.Sum256(independentDIDContext)
	if hex.EncodeToString(sum[:]) != contextDigest {
		return false
	}
	var root struct {
		Context map[string]any `json:"@context"`
	}
	if json.Unmarshal(independentDIDContext, &root) != nil {
		return false
	}
	_, term := root.Context[unusedTerm]
	_, vocab := root.Context["@vocab"]
	return len(root.Context) > 0 && !term && !vocab
}
func judgeBaseContext(out BaseContextResult, input string) core.Observation {
	raw, _ := json.Marshal(out)
	o := core.Observation{Statement: "did11-cr20260305#remote-resource-integrity.1", Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual local base-context API returns the declared DID 1.1 URL and independently pinned exact context bytes", Detail: "Direct pinned library embedded-context operation. The byte digest is independently fixed by the publication and downloaded W3C oracle, not the subject's digest constant. Selected local base-context availability/integrity only; consumer wiring, remote/custom context retrieval, full JSON-LD expansion/RDF and operational trust are not established."}
	if !contextOracleReady() || out.Operation != "github.com/sage-x-project/did-go/jsonld.BaseContext" || out.Version != "1.1" {
		return o
	}
	o.Verdict = core.Fail
	if out.Error == "" && out.URL == did11Context && bytes.Equal(out.Data, independentDIDContext) {
		o.Verdict = core.Pass
	}
	return o
}
func unknownConsumerFixture() ConsumptionRequest {
	return ConsumptionRequest{Data: []byte(`{"@context":"` + did11Context + `","id":"did:sage:web:registry.example:agent-1","inspectionNote":"public test term"}`), MediaType: "application/did"}
}
func judgeUnknownConsumer(q ConsumptionRequest, c ConsumptionCapture, input string) core.Observation {
	raw, _ := json.Marshal(c)
	o := core.Observation{Statement: "did11-cr20260305#json-ld-processors.8", Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual selected JSON-LD consumer removes the independently undefined root term and records the dropped term", Detail: "Literal base-context input and unchanged default consumer. Independent hash-pinned W3C context has no inspectionNote or @vocab definition. Checks this root term's removal and id/context retention; unknown remote contexts, nested scoped contexts and full JSON-LD/RDF processing remain unestablished."}
	if !contextOracleReady() || !sameConsumerCall(c, q) {
		return o
	}
	if c.Error != "" || c.CaptureError != "" {
		return o
	}
	o.Verdict = core.Fail
	model, e := parse(c.Model)
	entries, err := parse(c.Entries)
	want, _ := core.ParseJSON([]byte(`{"id":"did:sage:web:registry.example:agent-1"}`))
	equal, _ := checks.EqualJSON(model.Value(), want)
	ctx, present := entries.Get("@context")
	if e == nil && err == nil && equal && c.Version == "1.1" && c.JSONLD && reflect.DeepEqual(c.DroppedTerms, []string{unusedTerm}) && present && ctx.Kind == core.KindString && ctx.Str == did11Context && len(entries.Members) == 1 {
		o.Verdict = core.Pass
	}
	return o
}
func unknownProducerFixtures() (TypedProductionRequest, TypedProductionRequest) {
	good := TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:agent-1"}, JSONLD: true}
	bad := good
	bad.Fields = []TypedMember{{Name: unusedTerm, Value: TypedValue{Kind: "string", Text: "public test term"}}}
	return good, bad
}
func judgeUnknownProducer(pair producerContextPair, input string) core.Observation {
	raw, _ := json.Marshal(pair)
	good, bad := unknownProducerFixtures()
	o := core.Observation{Statement: "did11-cr20260305#json-ld-processors.6", Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual default JSON-LD producer avoids returning a document with the independently undefined root term", Detail: "Actual accepted control and one undefined root term input. Fixed W3C context bytes supply term definitions independently. No strict producer option is silently enabled; the default SAGE-selected producer's result remains unchanged. A recommended behavior failure is preserved. Refusal without output or valid removal is allowed. Error plus partial output is ERROR; unfamiliar added context is NOT_SUPPORTED. This is not full JSON-LD processing or SAGE resolver ingress evidence."}
	if !contextOracleReady() || !attributedContextInput(pair.Positive, good) || !attributedContextInput(pair.Negative, bad) {
		return o
	}
	if contextOutput(pair.Positive.Calls[0], good) != core.Pass {
		return o
	}
	call := pair.Negative.Calls[0]
	if call.Error != "" {
		if len(call.Output) == 0 {
			o.Verdict = core.Pass
		}
		return o
	}
	if call.MediaType != "application/did" || len(call.Output) == 0 {
		return o
	}
	value, e := core.ParseJSON(call.Output)
	if e != nil || value.Kind != core.KindObject || len(checks.DuplicateMembers(value)) > 0 {
		o.Verdict = core.Fail
		return o
	}
	ctx, present := value.Get("@context")
	if !present {
		o.Verdict = core.Fail
		return o
	}
	if ctx.Kind != core.KindString || ctx.Str != did11Context {
		o.Verdict = core.NotSupported
		return o
	}
	if _, present = value.Get(unusedTerm); present {
		o.Verdict = core.Fail
		return o
	}
	if contextOutput(call, good) == core.Pass {
		o.Verdict = core.Pass
	} else {
		o.Verdict = core.NotSupported
	}
	return o
}
func appendLibraryContextCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	baseID := "did11-cr20260305#remote-resource-integrity.1"
	consumerID := "did11-cr20260305#json-ld-processors.8"
	producerID := "did11-cr20260305#json-ld-processors.6"
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/library-context-cache", Profile: p.Name, Statements: []string{baseID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		input := `{"version":"1.1","url":"` + did11Context + `","sha256":"` + contextDigest + `"}`
		s, ok := target.(BaseContextSubject)
		if !ok {
			return libraryUnavailable([]string{baseID}, core.NotSupported, "no local base-context observer", input, nil)
		}
		out, e := s.InspectBaseContext(ctx)
		if e != nil {
			return libraryUnavailable([]string{baseID}, core.Error, e.Error(), input, out)
		}
		return []core.Observation{judgeBaseContext(out, input)}
	}}, core.Case{ID: p.Name + "/sage-resolution/library-context-consumer-unknown", Profile: p.Name, Statements: []string{consumerID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := unknownConsumerFixture()
		input, _ := json.Marshal(q)
		s, ok := target.(ConsumptionSubject)
		if !ok {
			return libraryUnavailable([]string{consumerID}, core.NotSupported, "no direct consumer", string(input), nil)
		}
		out, e := s.InspectConsumption(ctx, q)
		if e != nil {
			return libraryUnavailable([]string{consumerID}, core.Error, e.Error(), string(input), out)
		}
		return []core.Observation{judgeUnknownConsumer(q, out, string(input))}
	}}, core.Case{ID: p.Name + "/sage-resolution/library-context-producer-unknown", Profile: p.Name, Statements: []string{producerID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		good, bad := unknownProducerFixtures()
		input, _ := json.Marshal(producerContextFixture{Name: "undefined-root-term", Positive: good, Negative: bad})
		pair := producerContextPair{}
		s, ok := target.(TypedProductionSubject)
		if !ok {
			return libraryUnavailable([]string{producerID}, core.NotSupported, "no direct producer", string(input), pair)
		}
		out, e := s.InspectTypedProduction(ctx, good)
		pair.Positive = out
		if e != nil {
			return libraryUnavailable([]string{producerID}, core.Error, e.Error(), string(input), pair)
		}
		out, e = s.InspectTypedProduction(ctx, bad)
		pair.Negative = out
		if e != nil {
			return libraryUnavailable([]string{producerID}, core.Error, e.Error(), string(input), pair)
		}
		return []core.Observation{judgeUnknownProducer(pair, string(input))}
	}})
}
