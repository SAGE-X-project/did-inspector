package sageresolution

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
)

//go:embed expansion_repair.json
var expansionRepairManifestBytes []byte

// ExpansionRepairManifest binds the independent review to the selected source.
// A new source revision requires a new review, not a generic inferred PASS.
type ExpansionRepairManifest struct {
	Module        string            `json:"module"`
	Version       string            `json:"version"`
	Revision      string            `json:"revision"`
	Sum           string            `json:"sum"`
	SourceFiles   map[string]string `json:"source_files"`
	FixtureSHA256 string            `json:"fixture_sha256"`
}

type expansionRepairEvidence struct {
	Source  IntegerSourceResult      `json:"source"`
	Audit   sourcearith.ServiceAudit `json:"audit"`
	Edges   [][]string               `json:"edges"`
	Runtime []RoutingResult          `json:"runtime"`
	Items   []itemCondition          `json:"items"`
	Error   string                   `json:"analysis_error,omitempty"`
}

func expansionRepairManifest() (ExpansionRepairManifest, error) {
	var m ExpansionRepairManifest
	err := json.Unmarshal(expansionRepairManifestBytes, &m)
	return m, err
}

func repairSourceRequest(m ExpansionRepairManifest) IntegerSourceRequest {
	q := expansionSourceRequest()
	q.Module = m.Module
	q.Version = m.Version
	return q
}

func repairSource(ctx context.Context, v IntegerSourceResult, m ExpansionRepairManifest) (sourcearith.ServiceAudit, [][]string, error) {
	fail := func(s string) (sourcearith.ServiceAudit, [][]string, error) {
		return sourcearith.ServiceAudit{}, nil, fmt.Errorf("%s", s)
	}
	q := repairSourceRequest(m)
	if !reflect.DeepEqual(v.Request, q) || v.Module != m.Module || v.Version != m.Version || v.Sum != m.Sum || v.Replaced || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return fail("unbound source identity")
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, m.Module+"@"+m.Version)
	if err != nil || sum != m.Sum {
		return fail("unbound source archive")
	}
	selected := sourcearith.SourceFiles(files, q.Packages)
	if len(selected) != len(m.SourceFiles) || len(v.Files) != len(selected) || len(selected) == 0 {
		return fail("incomplete reviewed source")
	}
	for name, b := range selected {
		if !bytes.Equal(b, v.Files[name]) || fmt.Sprintf("%x", sha256.Sum256(b)) != m.SourceFiles[name] {
			return fail("source differs from independent reviewed bytes")
		}
	}
	p := sourcearith.NewProgram(ctx, m.Module, v.Files)
	if _, err := p.Import(m.Module + "/resolver"); err != nil {
		return fail("source type check failed")
	}
	a := p.ExpansionAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 || !a.Steps[0].Correct || !a.Steps[1].Correct || a.Roles["method_extensions"] != "true" || a.Roles["service_extensions"] != "true" {
		return fail("unbound expansion guard or typed public fields")
	}
	// These edges supplement the reviewed complete file bindings. Reading Extra
	// or observing an unrelated helper call alone is never sufficient.
	edges := [][]string{}
	for _, names := range [][2]string{{"expand", "expandJSONMap"}, {"expandMethod", "expandJSONMap"}, {"expandJSONMap", "absoluteString"}, {"expandJSONMap", "expandJSONValue"}, {"expandJSONValue", "expandJSONMap"}, {"expandJSONValue", "expandJSONValue"}} {
		edge := []string{m.Module + "/resolver." + names[0], m.Module + "/resolver." + names[1]}
		if !p.Calls(edge[0], edge[1]) {
			return fail("missing recursive public map call edge")
		}
		edges = append(edges, edge)
	}
	return a, edges, nil
}

func judgeRepairedExpansion(ctx context.Context, e expansionRepairEvidence, m ExpansionRepairManifest, input string) []core.Observation {
	ids := []string{expansionSourceIDs[1], itemExpansionID}
	obs := libraryUnavailable(ids, core.Error, "Independent reviewed-source binding and typed call context, corroborated by the five unchanged literal expansion fixtures and five qualifying relative IDs. Public output only; no full RFC3986, operational authority, numeric/JWK/endpoint certification or SAGE consumer adoption. Historical reports are separate.", input, nil)
	if fmt.Sprintf("%x", sha256.Sum256(expansionSourceBytes)) != m.FixtureSHA256 {
		e.Error = "frozen fixtures changed"
	} else {
		var err error
		e.Audit, e.Edges, err = repairSource(ctx, e.Source, m)
		if err != nil {
			e.Error = err.Error()
		} else {
			valid, missing := expansionSourceRuntime(e.Runtime)
			items, qualifying := expansionItemConditions(e.Runtime)
			e.Items = items
			if !valid || missing || !qualifying || expansionItemVerdict(items) != core.Pass {
				e.Error = "missing or contradictory same-call runtime expansion"
			} else {
				for i := range obs {
					obs[i].Verdict = core.Pass
				}
			}
		}
	}
	if ctx.Err() != nil {
		e.Error = ctx.Err().Error()
		for i := range obs {
			obs[i].Verdict = core.Error
		}
	}
	raw, _ := json.Marshal(e)
	for i := range obs {
		obs[i].Observed = string(raw)
		obs[i].Expected = "Reviewed public field traversal and processing of all five literal relative object IDs; original fixtures and consumer input remain unchanged"
	}
	return obs
}

// RelativeExpansionProfile preserves the original profile and fixtures and
// selects a separate case for a separately identified repaired root module.
func RelativeExpansionProfile(name string) (core.Profile, error) {
	p, err := Profile(name)
	if err != nil {
		return p, err
	}
	if name != "did-1.1" {
		return core.Profile{}, fmt.Errorf("requires did-1.1")
	}
	m, err := expansionRepairManifest()
	if err != nil {
		return core.Profile{}, err
	}
	ids := []string{expansionSourceIDs[1], itemExpansionID}
	p.Cases = []core.Case{{ID: name + "/sage-resolution/repaired-relative-expansion", Profile: name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		q := repairSourceRequest(m)
		input, _ := json.Marshal(q)
		if !ok || !ok1 {
			return libraryUnavailable(ids, core.NotSupported, "requires source and literal routing observers", string(input), nil)
		}
		e := expansionRepairEvidence{Runtime: []RoutingResult{}, Items: []itemCondition{}}
		captured, sourceErr := source.InspectIntegerSource(ctx, q)
		e.Source = captured
		if sourceErr != nil {
			return libraryUnavailable(ids, core.Error, sourceErr.Error(), string(input), e)
		}
		for _, f := range expansionSourceFixtures() {
			v, callErr := routing.InspectRouting(ctx, expansionSourceRouting(f))
			e.Runtime = append(e.Runtime, v)
			if callErr != nil {
				return libraryUnavailable(ids, core.Error, callErr.Error(), string(input), e)
			}
		}
		return judgeRepairedExpansion(ctx, e, m, string(input))
	}}}
	return p, nil
}
