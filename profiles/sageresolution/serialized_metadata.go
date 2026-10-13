package sageresolution

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const resolutionSerializer = "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON"
const documentSerializer = "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON"

func metadataStatements() []string {
	return []string{resolutionPrefix + "metadata-structure.1", resolutionPrefix + "metadata-structure.2", resolutionPrefix + "metadata-structure.3", resolutionPrefix + "metadata-structure.4"}
}

// boundedInfraValue limits the serializability observation to ASCII strings
// and safe integer numbers. Other values need a separate numeric/Unicode
// observation; they are unsupported here, not prohibited by the standard.
func boundedInfraValue(v core.Value) bool {
	switch v.Kind {
	case core.KindString:
		return ascii(v.Str)
	case core.KindNumber:
		number, err := strconv.ParseInt(v.Number, 10, 64)
		return err == nil && number >= -9007199254740991 && number <= 9007199254740991
	case core.KindArray:
		for _, item := range v.Array {
			if !boundedInfraValue(item) {
				return false
			}
		}
	case core.KindObject:
		for _, item := range v.Object {
			if !ascii(item.Name) || !boundedInfraValue(item.Value) {
				return false
			}
		}
	}
	return true
}

func judgeMetadata(result MetadataResult, role, input string) []core.Observation {
	capture, identity := result.Resolution, resolutionSerializer
	if role == "document" {
		capture, identity = result.Document, documentSerializer
	}
	raw, _ := json.Marshal(result)
	ids := metadataStatements()
	value, parseError := core.ParseJSON(capture.Bytes)
	duplicate := parseError == nil && len(checks.DuplicateMembers(value)) > 0
	out := make([]core.Observation, 0, len(ids))
	for i, id := range ids {
		verdict := core.Pass
		detail := "Fresh direct " + identity + " output; selected " + role + " metadata only. Communicated JSON maps, string property names and recursive values are inspected independently. No generic adapter encoder, subject validator or prior verdict is used. Typed pre-serialization fidelity, input metadata, arbitrary Infra values, ECMAScript byte equality, history and deployed authority are unestablished."
		switch {
		case capture.Serializer != identity:
			verdict = core.Error
			detail = "missing or mismatched direct native serializer attribution"
		case capture.Error != "":
			verdict = core.Error
			if i == 3 {
				verdict = core.Fail
			}
			detail = "actual " + role + " serializer failure preserved; shape has no usable output: " + capture.Error
		case parseError != nil || duplicate || value.Kind != core.KindObject:
			verdict = core.Fail
			detail = "actual " + role + " serializer returned malformed JSON, duplicate properties or a non-map; original bytes retained"
		case i == 3 && !boundedInfraValue(value):
			verdict = core.NotSupported
			detail = "direct serializer output retained, but numeric/Unicode serializability is outside this ASCII and safe-integer observation; not a standard prohibition"
		}
		out = append(out, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Direct native output metadata is a string-keyed map of allowed values, serializable as JSON", Observed: string(raw), Detail: detail})
	}
	return out
}

func appendMetadataCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	scenarios := resultScenarios(rows)
	scenarios = append(scenarios,
		resultScenario{name: "dereference-method", request: Request{Function: "dereference", Input: rows[0].DID + "#sign", Accept: "application/did"}},
		resultScenario{name: "dereference-missing", request: Request{Function: "dereference", Input: rows[0].DID + "#missing", Accept: "application/did"}})
	for _, s := range scenarios {
		for _, role := range []string{"resolution", "document"} {
			record := rows[s.record]
			ids := metadataStatements()
			p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-metadata-" + s.name + "-" + role, Profile: p.Name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
				input, _ := json.Marshal(struct {
					Record  sageprojection.Record `json:"record"`
					Request Request               `json:"request"`
					Role    string                `json:"role"`
				}{record, s.request, role})
				missing := func(verdict core.Verdict, detail string) []core.Observation {
					out := unavailable(ids, verdict, detail)
					for i := range out {
						out[i].Input = string(input)
					}
					return out
				}
				subject, ok := target.(MetadataSubject)
				if !ok {
					return missing(core.NotSupported, "no direct native metadata serialization observation")
				}
				result, err := subject.InspectMetadata(ctx, record, s.request)
				if err != nil {
					return missing(core.Error, err.Error())
				}
				return judgeMetadata(result, role, string(input))
			}})
		}
	}
}
