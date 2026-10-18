package sageresolution

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
)

//go:embed resource_repair.json
var resourceRepairManifestBytes []byte

// ResourceRepairManifest binds this separate review to exact public module bytes.
type ResourceRepairManifest struct {
	Module        string            `json:"module"`
	Version       string            `json:"version"`
	Revision      string            `json:"revision"`
	Sum           string            `json:"sum"`
	SourceFiles   map[string]string `json:"source_files"`
	FixtureSHA256 string            `json:"fixture_sha256"`
}
type resourceRepairEvidence struct {
	Source  IntegerSourceResult      `json:"source"`
	Audit   sourcearith.ServiceAudit `json:"audit"`
	Edges   [][]string               `json:"edges"`
	Runtime []RoutingResult          `json:"runtime"`
	Error   string                   `json:"analysis_error,omitempty"`
}

func resourceRepairManifest() (ResourceRepairManifest, error) {
	var m ResourceRepairManifest
	err := json.Unmarshal(resourceRepairManifestBytes, &m)
	return m, err
}
func resourceRepairSourceRequest(m ResourceRepairManifest) IntegerSourceRequest {
	q := urlRoleRequest()
	q.Packages = []string{"dereferencer", "relyingparty", "did", "document", "internal/multiformats", "internal/wire", "representation", "resolution", "spec", "vm"}
	q.Module = m.Module
	q.Version = m.Version
	return q
}
func resourceRepairAudit(a sourcearith.ServiceAudit) error {
	var w sourcearith.ServiceAudit
	if json.Unmarshal(urlRoleWitness, &w) != nil || !reflect.DeepEqual(a.Roots, w.Roots) || !reflect.DeepEqual(a.Roles, w.Roles) || !reflect.DeepEqual(a.CallPaths, w.CallPaths) || len(a.Unknown) != 0 || len(a.Steps) != 2 {
		return fmt.Errorf("unbound typed URL context")
	}
	step := a.Steps[0]
	if step.Kind != w.Steps[0].Kind || !step.Correct || !reflect.DeepEqual(step.Expressions, []string{"u.WithoutFragment()"}) || !reflect.DeepEqual(a.Steps[1], w.Steps[1]) {
		return fmt.Errorf("missing primary URL adjustment or changed extraction context")
	}
	// Other frames may reflect earlier independently reviewed repairs. Bind the
	// twelve critical frames and all 44 complete source files, not a historical
	// total function count or a subject-supplied correctness assertion.
	names := append([]string{}, w.Roots...)
	names = append(names, IntegerSourceModule+"/did.("+IntegerSourceModule+"/did.DIDURL).WithoutFragment", IntegerSourceModule+"/dereferencer.(*"+IntegerSourceModule+"/dereferencer.Dereferencer).fragment")
	for _, name := range names {
		if a.Frames[name] == "" || a.Frames[name] != w.Frames[name] {
			return fmt.Errorf("changed critical URL frame: %s", name)
		}
	}
	for _, h := range a.Frames {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 || fmt.Sprintf("%x", b) != h {
			return fmt.Errorf("invalid function frame")
		}
	}
	return nil
}
func resourceRepairSource(ctx context.Context, v IntegerSourceResult, m ResourceRepairManifest) (sourcearith.ServiceAudit, [][]string, error) {
	fail := func(s string) (sourcearith.ServiceAudit, [][]string, error) {
		return sourcearith.ServiceAudit{}, nil, fmt.Errorf("%s", s)
	}
	if !reflect.DeepEqual(v.Request, resourceRepairSourceRequest(m)) || v.Module != m.Module || v.Version != m.Version || v.Sum != m.Sum || v.Replaced || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return fail("unbound source identity")
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, m.Module+"@"+m.Version)
	if err != nil || sum != m.Sum {
		return fail("unbound source archive")
	}
	selected := sourcearith.SourceFiles(files, v.Request.Packages)
	if len(selected) != 44 || len(selected) != len(m.SourceFiles) || len(v.Files) != len(selected) {
		return fail("incomplete reviewed source")
	}
	for name, b := range selected {
		if !bytes.Equal(b, v.Files[name]) || fmt.Sprintf("%x", sha256.Sum256(b)) != m.SourceFiles[name] {
			return fail("source differs from independent reviewed bytes")
		}
	}
	p := sourcearith.NewProgram(ctx, m.Module, v.Files)
	for _, name := range []string{"dereferencer", "relyingparty"} {
		if _, err := p.Import(m.Module + "/" + name); err != nil {
			return fail("source type check failed: " + err.Error())
		}
	}
	a := p.URLRolesAudit()
	if err := resourceRepairAudit(a); err != nil {
		return fail(err.Error())
	}
	edge := []string{m.Module + "/dereferencer.(*" + m.Module + "/dereferencer.Dereferencer).resource", m.Module + "/did.(" + m.Module + "/did.DIDURL).WithoutFragment"}
	if !p.Calls(edge[0], edge[1]) {
		return fail("missing primary URL adjustment call edge")
	}
	return a, [][]string{edge}, nil
}
func judgeRepairedResource(ctx context.Context, e resourceRepairEvidence, m ResourceRepairManifest, input string) []core.Observation {
	obs := libraryUnavailable(urlRoleIDs[:1], core.Error, "Independently reviewed typed primary URL argument and seven unchanged literal native requests, including six passive handler captures. NOT_FOUND is diagnostic, not proof. No arbitrary handler media-fragment processing, relying-party runtime certification, full URI semantics, operational authority or SAGE consumer adoption. Historical results remain separate.", input, nil)
	if fmt.Sprintf("%x", sha256.Sum256(urlRoleBytes)) != m.FixtureSHA256 {
		e.Error = "frozen fixtures changed"
	} else {
		var err error
		e.Audit, e.Edges, err = resourceRepairSource(ctx, e.Source, m)
		if err != nil {
			e.Error = err.Error()
		} else {
			valid, missing := urlHandlerRuntime(e.Runtime)
			if valid {
				for i, f := range urlRoleFixtures().Handlers {
					r := e.Runtime[i].Result
					if f.Error != "" {
						valid = valid && (len(r.Snapshot) == 0 || string(r.Snapshot) == "null") && r.ContentKind == "" && r.ReturnedID == ""
					} else {
						var expected struct {
							ID string `json:"id"`
						}
						_ = json.Unmarshal(f.Content, &expected)
						valid = valid && optionJSONEqual(r.Snapshot, string(f.Content)) && r.ReturnedID == expected.ID
					}
				}
			}
			if !valid || missing {
				e.Error = "missing or contradictory same-call primary URL evidence"
			} else {
				obs[0].Verdict = core.Pass
			}
		}
	}
	if ctx.Err() != nil {
		e.Error = ctx.Err().Error()
		obs[0].Verdict = core.Error
	}
	raw, _ := json.Marshal(e)
	obs[0].Observed = string(raw)
	obs[0].Expected = "Fragment-free actual handler arguments with original path/query bytes, document and options preserved"
	return obs
}

// PrimaryResourceProfile selects only the separately repaired URL clause.
// The original profiles, fixtures, pins and historical failures remain intact.
func PrimaryResourceProfile(name string) (core.Profile, error) {
	p, err := Profile(name)
	if err != nil {
		return p, err
	}
	if name != "did-1.1" {
		return core.Profile{}, fmt.Errorf("requires did-1.1")
	}
	m, err := resourceRepairManifest()
	if err != nil {
		return core.Profile{}, err
	}
	p.Cases = []core.Case{{ID: name + "/sage-resolution/repaired-primary-resource-url", Profile: name, Statements: urlRoleIDs[:1], Run: func(ctx context.Context, target core.Subject) []core.Observation {
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		q := resourceRepairSourceRequest(m)
		input, _ := json.Marshal(q)
		if !ok || !ok1 {
			return libraryUnavailable(urlRoleIDs[:1], core.NotSupported, "requires source and literal routing observers", string(input), nil)
		}
		e := resourceRepairEvidence{Runtime: []RoutingResult{}}
		captured, sourceErr := source.InspectIntegerSource(ctx, q)
		e.Source = captured
		if sourceErr != nil {
			return libraryUnavailable(urlRoleIDs[:1], core.Error, sourceErr.Error(), string(input), e)
		}
		for _, f := range urlRoleFixtures().Handlers {
			v, callErr := routing.InspectRouting(ctx, urlRoleRouting(f))
			e.Runtime = append(e.Runtime, v)
			if callErr != nil {
				return libraryUnavailable(urlRoleIDs[:1], core.Error, callErr.Error(), string(input), e)
			}
		}
		return judgeRepairedResource(ctx, e, m, string(input))
	}}}
	return p, nil
}
