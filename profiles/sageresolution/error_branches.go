package sageresolution

import (
	"context"
	"encoding/json"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

type branchScenario struct {
	name    string
	record  int
	request Request
	branch  string
}

func branchStatements(branch string) []string {
	numbers := []string{"36", "37", "38", "39"}
	section := "resolving-algorithm."
	switch branch {
	case "missing":
		numbers = []string{"6", "7", "8", "9"}
		section = "dereferencing-algorithm-resource."
	case "deactivated":
		numbers = []string{"22", "23", "24", "25"}
	}
	out := make([]string, 0, 4)
	for _, n := range numbers {
		out = append(out, resolutionPrefix+section+n)
	}
	return out
}
func judgeBranch(result Result, branch, input string) []core.Observation {
	ids := branchStatements(branch)
	unavailableInput := func(detail string) []core.Observation {
		out := unavailable(ids, core.Error, detail)
		for i := range out {
			out[i].Input = input
		}
		return out
	}
	if result.Exchange != nil || result.Native != nil {
		return unavailableInput("native branch output required")
	}
	md, err := parse(result.Metadata)
	if err != nil {
		return unavailableInput(err.Error())
	}
	cm, err := parse(result.ContentMetadata)
	if err != nil {
		return unavailableInput(err.Error())
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return unavailableInput(err.Error())
	}
	noContent := nativeNullDocument(result)
	marker, _ := cm.Get("deactivated")
	_, hasError := md.Get("error")
	keyword := "INTERNAL_ERROR"
	if branch == "missing" {
		keyword = "NOT_FOUND"
		value, err := core.ParseJSON(result.Raw)
		noContent = noContent && err == nil && value.Kind == core.KindNull
	}
	exact := nativeErrorDescriptor(md) && errorName(md) == "https://www.w3.org/ns/did#"+keyword
	second := exact
	last := cm.Len() == 0
	if branch == "deactivated" {
		second = !hasError
		last = marker.Kind == core.KindBool && marker.Bool
	}
	predicates := []bool{second && noContent && last, second, noContent, last}
	out := make([]core.Observation, 0, 4)
	for i, id := range ids {
		verdict := core.Pass
		if !predicates[i] {
			verdict = core.Fail
		}
		out = append(out, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Selected native branch outcome: independent metadata, absent content and content-metadata assertions", Observed: string(raw), Detail: "Fresh actual native resolve/dereference call on a fixed public Source. Scenario selected before execution; no outcome-derived inapplicability, repaired output or copied verdict. Missing DID is a fixture record mismatch, not VDR authority. Unexpected Source failure is an ordinary Go error mapped by the actual SAGE wrapper; internal algorithm steps, deployment and other branches are unestablished."})
	}
	return out
}
func appendBranchCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	scenarios := []branchScenario{
		{name: "missing-did", request: Request{Function: "dereference", Input: "did:sage:web:registry.example:missing-agent"}, branch: "missing"},
		{name: "deactivated", record: 4, request: Request{Function: "resolve", Input: rows[4].DID}, branch: "deactivated"},
		{name: "unexpected-source", request: Request{Function: "resolve", Input: rows[0].DID, SourceFailure: "fixture.unexpected"}, branch: "unexpected"},
	}
	for _, s := range scenarios {
		record := rows[s.record]
		ids := branchStatements(s.branch)
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-branch-" + s.name, Profile: p.Name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, s.request})
			missing := func(v core.Verdict, detail string) []core.Observation {
				out := unavailable(ids, v, detail)
				for i := range out {
					out[i].Input = string(input)
				}
				return out
			}
			subject, ok := target.(Subject)
			if !ok {
				return missing(core.NotSupported, "no native branch observation")
			}
			actual, err := subject.InspectResolution(ctx, record, s.request)
			if err != nil {
				return missing(core.Error, err.Error())
			}
			return judgeBranch(actual, s.branch, string(input))
		}})
	}
}
