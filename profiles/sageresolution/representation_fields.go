package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

var representationStatements = []string{"did11-cr20260305#json-ld-processors.3", "did11-cr20260305#json-ld-processors.4", "did11-cr20260305#json-ld-processors.7", "did11-cr20260305#production.4"}

const did11Context = "https://www.w3.org/ns/did/v1.1"

func representationContext(value core.Value) bool {
	if value.Kind == core.KindString {
		return value.Str == did11Context
	}
	return value.Kind == core.KindArray && len(value.Array) > 0 && value.Array[0].Kind == core.KindString && value.Array[0].Str == did11Context
}
func judgeRepresentation(result Result, input string) []core.Observation {
	missing := func(detail string) []core.Observation {
		out := unavailable(representationStatements, core.Error, detail)
		for i := range out {
			out[i].Input = input
		}
		return out
	}
	if result.Exchange != nil || result.Native != nil || !result.HasContent || result.ContentKind != "document" {
		return missing("fresh native document representation required")
	}
	md, err := parse(result.Metadata)
	if err != nil {
		return missing(err.Error())
	}
	if _, failed := md.Get("error"); failed {
		return missing("native resolver returned an error")
	}
	doc, err := parse(result.Raw)
	if err != nil {
		return missing("unusable actual producer bytes: " + err.Error())
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return missing(err.Error())
	}
	ctx, present := doc.Get("@context")
	ct, _ := md.Get("contentType")
	mediaType, _, mediaError := mime.ParseMediaType(ct.Str)
	media := ct.Kind == core.KindString && ascii(ct.Str) && mediaError == nil && mediaType == "application/did"
	validContext := present && representationContext(ctx)
	verdicts := []core.Verdict{core.Pass, core.Pass, core.Pass, core.Pass}
	if !present {
		verdicts[0] = core.Fail
	}
	if !validContext {
		verdicts[1] = core.Fail
	}
	if validContext && ctx.Kind == core.KindArray {
		for _, item := range ctx.Array[1:] {
			if !boundedInfraValue(item) {
				verdicts[1] = core.NotSupported
			}
		}
	}
	if !media {
		verdicts[2] = core.Fail
		verdicts[3] = core.Fail
	}
	out := make([]core.Observation, 0, 4)
	for i, id := range representationStatements {
		out = append(out, core.Observation{Statement: id, Verdict: verdicts[i], Input: input, Expected: "Actual application/did producer bytes include the DID 1.1 context and downstream media type", Observed: string(raw), Detail: "Fresh actual native ResolveString application/did Raw bytes and returned resolution metadata. Context presence, serialized string/array first value and media type only; bounded ASCII/safe-integer JSON context suffix values. No getter equality, projection verdict or subject validator is an oracle. Full JSON production/input preservation, JSON-LD processing/term semantics, remote context retrieval, registration, authority and whole conformance are unestablished."})
	}
	return out
}
func appendRepresentationCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-representation-record-%d", p.Name, i), Profile: p.Name, Statements: append([]string{}, representationStatements...), Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			missing := func(v core.Verdict, detail string) []core.Observation {
				out := unavailable(representationStatements, v, detail)
				for i := range out {
					out[i].Input = string(input)
				}
				return out
			}
			subject, ok := target.(Subject)
			if !ok {
				return missing(core.NotSupported, "no actual native representation operation")
			}
			result, err := subject.InspectResolution(ctx, record, q)
			if err != nil {
				return missing(core.Error, err.Error())
			}
			return judgeRepresentation(result, string(input))
		}})
	}
}
