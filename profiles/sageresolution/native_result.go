package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const resolutionPrefix = "res10-crd20261001#"

type resultScenario struct {
	name         string
	record       int
	request      Request
	errorKeyword string
	branch       string
}

func resultStatements(s resultScenario) []string {
	ids := []string{resolutionPrefix + "resolving.4", resolutionPrefix + "resolving.5"}
	if s.errorKeyword == "" {
		return append(ids, resolutionPrefix+"resolving.1", resolutionPrefix+"did-document-metadata.7")
	}
	switch s.branch {
	case "invalid":
		return append(ids, resolutionPrefix+"resolving-algorithm.1", resolutionPrefix+"resolving-algorithm.3", resolutionPrefix+"resolving-algorithm.4")
	case "method":
		return append(ids, resolutionPrefix+"resolving-algorithm.5", resolutionPrefix+"resolving-algorithm.6", resolutionPrefix+"resolving-algorithm.7", resolutionPrefix+"resolving-algorithm.8")
	case "missing":
		return append(ids, resolutionPrefix+"resolving-algorithm.18", resolutionPrefix+"resolving-algorithm.20", resolutionPrefix+"resolving-algorithm.21")
	}
	return ids
}
func nativeNullDocument(o Result) bool {
	if o.HasContent || o.ReturnedID != "" || o.ContentKind != "" {
		return false
	}
	if len(o.Snapshot) == 0 {
		return true
	}
	v, err := core.ParseJSON(o.Snapshot)
	return err == nil && v.Kind == core.KindNull
}
func nativeErrorDescriptor(md core.DocumentJSON) bool {
	e, present := md.Get("error")
	if !present || e.Kind != core.KindObject {
		return false
	}
	typ, _ := e.Get("type")
	return typ.Kind == core.KindString && checks.IsAbsoluteURI(typ.Str)
}
func judgeNativeResult(o Result, s resultScenario, input string) []core.Observation {
	ids := resultStatements(s)
	fail := func(detail string) []core.Observation {
		out := unavailable(ids, core.Error, detail)
		for i := range out {
			out[i].Input = input
		}
		return out
	}
	if o.Exchange != nil || o.Native != nil {
		return fail("requires a fresh native resolve result, not an HTTP/comparison result")
	}
	md, err := parse(o.Metadata)
	if err != nil {
		return fail(err.Error())
	}
	cm, err := parse(o.ContentMetadata)
	if err != nil {
		return fail(err.Error())
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return fail(err.Error())
	}
	failed := s.errorKeyword != ""
	descriptor := nativeErrorDescriptor(md)
	e, _ := md.Get("error")
	typ, _ := e.Get("type")
	exactError := descriptor && typ.Str == "https://www.w3.org/ns/did#"+s.errorKeyword
	emptyMetadata := cm.Len() == 0
	noDocument := nativeNullDocument(o)
	wholeError := exactError && noDocument && emptyMetadata
	out := make([]core.Observation, 0, len(ids))
	for _, id := range ids {
		pass, applicable := true, true
		switch id {
		case resolutionPrefix + "resolving.4":
			pass = !failed || md.Len() > 0
		case resolutionPrefix + "resolving.5":
			applicable = failed
			pass = descriptor
		case resolutionPrefix + "resolving.1":
			d, err := parse(o.Snapshot)
			identifier, _ := d.Get("id")
			_, hasError := md.Get("error")
			pass = err == nil && o.HasContent && o.ContentKind == "document" && !hasError && identifier.Kind == core.KindString && identifier.Str == s.request.Input && o.ReturnedID == s.request.Input && checks.IsDID(identifier.Str)
		case resolutionPrefix + "did-document-metadata.7":
			deactivated, present := cm.Get("deactivated")
			applicable = present
			pass = deactivated.Kind == core.KindBool && !deactivated.Bool
		case resolutionPrefix + "resolving-algorithm.1", resolutionPrefix + "resolving-algorithm.5", resolutionPrefix + "resolving-algorithm.18":
			pass = wholeError
		case resolutionPrefix + "resolving-algorithm.6":
			pass = exactError
		case resolutionPrefix + "resolving-algorithm.3", resolutionPrefix + "resolving-algorithm.7", resolutionPrefix + "resolving-algorithm.20":
			pass = noDocument
		case resolutionPrefix + "resolving-algorithm.4", resolutionPrefix + "resolving-algorithm.8", resolutionPrefix + "resolving-algorithm.21":
			pass = emptyMetadata
		}
		verdict := core.Pass
		if !applicable {
			verdict = core.NotApplicable
		} else if !pass {
			verdict = core.Fail
		}
		out = append(out, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Clause-specific native resolution result for independently selected success/error branch", Observed: string(raw), Detail: "Fresh actual ResolveString output on fixed public record Source. Selected success or expected fixture error branch only; metadata is a typed native value marshaled by the adapter, not proof of the subject serializer. Entire document conformance, internal Source call sequence, deployed authority/history and other error branches are unestablished. Optional inactive-marker format is NOT_APPLICABLE when absent; this does not resolve separate SAGE-required metadata failures. No output is repaired or prior verdict copied."})
	}
	return out
}
func resultScenarios(rows []sageprojection.Record) []resultScenario {
	var scenarios []resultScenario
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		scenarios = append(scenarios, resultScenario{name: fmt.Sprintf("active-record-%d", i), record: i, request: Request{Function: "resolve", Input: record.DID, Accept: "application/did"}})
	}
	scenarios = append(scenarios, []resultScenario{
		{name: "invalid-input", request: Request{Function: "resolve", Input: "not-a-did", Accept: "application/did"}, errorKeyword: "INVALID_DID", branch: "invalid"},
		{name: "unsupported-method", request: Request{Function: "resolve", Input: "did:example:missing", Accept: "application/did"}, errorKeyword: "METHOD_NOT_SUPPORTED", branch: "method"},
		{name: "missing-record", request: Request{Function: "resolve", Input: "did:sage:web:registry.example:missing-agent", Accept: "application/did"}, errorKeyword: "NOT_FOUND", branch: "missing"},
		{name: "stale-source", request: Request{Function: "resolve", Input: rows[0].DID, Accept: "application/did", SourceFailure: "record.stale"}, errorKeyword: "INTERNAL_ERROR"},
		{name: "unsupported-accept", request: Request{Function: "resolve", Input: rows[0].DID, Accept: "text/html"}, errorKeyword: "FEATURE_NOT_SUPPORTED"},
	}...)
	return scenarios
}

func appendNativeResultCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for _, s := range resultScenarios(rows) {
		record := rows[s.record]
		ids := resultStatements(s)
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-result-" + s.name, Profile: p.Name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, s.request})
			subject, ok := target.(Subject)
			if !ok {
				obs := unavailable(ids, core.NotSupported, "no native resolve observation operation")
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			actual, err := subject.InspectResolution(ctx, record, s.request)
			if err != nil {
				obs := unavailable(ids, core.Error, err.Error())
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			return judgeNativeResult(actual, s, string(input))
		}})
	}
}
