package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

var multihashIDs = []string{"cid10#multihash.2", "cid10#multihash.3"}

const MultihashRole = "Inspector-owned direct internal multiformats component probe; not a SAGE production caller"

type MultihashRequest struct {
	Operation string `json:"operation"`
	Code      uint64 `json:"code"`
	Digest    []byte `json:"digest"`
	Encoded   []byte `json:"encoded"`
}

const ComponentObserverModule = "github.com/sage-x-project/did-go/inspectorprobe"

type ComponentObserver struct {
	Module             string `json:"module"`
	Version            string `json:"version"`
	Replacement        string `json:"replacement"`
	ReplacementVersion string `json:"replacement_version"`
	ReplacementSum     string `json:"replacement_sum"`
	Compiler           string `json:"compiler"`
}

type MultihashResult struct {
	Request   MultihashRequest  `json:"request"`
	Observer  ComponentObserver `json:"observer"`
	Operation string            `json:"operation"`
	Role      string            `json:"role"`
	Encoded   []byte            `json:"encoded"`
	Code      uint64            `json:"code"`
	Digest    []byte            `json:"digest"`
	Error     string            `json:"error,omitempty"`
}
type MultihashSubject interface {
	core.Subject
	InspectMultihash(context.Context, MultihashRequest) (MultihashResult, error)
}
type multihashFixture struct {
	Name       string           `json:"name"`
	Statement  string           `json:"statement"`
	Request    MultihashRequest `json:"request"`
	Encoded    []byte           `json:"expected_encoded"`
	Code       uint64           `json:"expected_code"`
	Digest     []byte           `json:"expected_digest"`
	Reject     bool             `json:"reject"`
	Diagnostic bool             `json:"diagnostic"`
}
type multihashEvidence struct {
	Source IntegerSourceResult        `json:"source"`
	Calls  map[string]MultihashResult `json:"calls"`
	Errors map[string]string          `json:"call_errors"`
	Error  string                     `json:"analysis_error,omitempty"`
}

//go:embed multihash.json
var multihashBytes []byte

func multihashFixtures() []multihashFixture {
	out := []multihashFixture{}
	_ = json.Unmarshal(multihashBytes, &out)
	return out
}
func multihashSourceRequest() IntegerSourceRequest {
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"internal/multiformats"}}
}
func multihashSourceReady(v IntegerSourceResult) bool {
	if !reflect.DeepEqual(v.Request, multihashSourceRequest()) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Replaced || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return false
	}
	files, sum, e := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if e != nil || sum != IntegerSourceSum {
		return false
	}
	selected := sourcearith.SourceFiles(files, v.Request.Packages)
	if len(selected) != 3 || len(selected) != len(v.Files) {
		return false
	}
	for name, data := range selected {
		if !bytes.Equal(data, v.Files[name]) {
			return false
		}
	}
	return true
}
func multihashCallVerdict(f multihashFixture, v MultihashResult) core.Verdict {
	operation := IntegerSourceModule + "/internal/multiformats."
	if f.Request.Operation == "encode" {
		operation += "EncodeMultihash"
	} else {
		operation += "DecodeMultihash"
	}
	observer := v.Observer
	if observer.ReplacementVersion == "" {
		observer.ReplacementVersion = "(devel)"
	}
	if observer != (ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", ReplacementVersion: "(devel)", Compiler: "go1.26.8"}) || !reflect.DeepEqual(v.Request, f.Request) || v.Role != MultihashRole || v.Operation != operation {
		return core.Error
	}
	if f.Diagnostic {
		return core.NotApplicable
	}
	if f.Reject {
		if v.Error != "" {
			return core.Pass
		}
		return core.Fail
	}
	if v.Error != "" {
		return core.Fail
	}
	if f.Request.Operation == "encode" {
		if bytes.Equal(v.Encoded, f.Encoded) {
			return core.Pass
		}
		return core.Fail
	}
	if v.Code == f.Code && bytes.Equal(v.Digest, f.Digest) {
		return core.Pass
	}
	return core.Fail
}
func judgeMultihash(ctx context.Context, e multihashEvidence, input string) []core.Observation {
	obs := libraryUnavailable(multihashIDs, core.Error, "Direct calls to the original pinned internal multiformats component via an Inspector-owned module, not SAGE production use. Independently fixed bytes cover four defined code/length pairs and declared/expected/actual length mismatches. Unknown-code and invalid-encode inputs remain diagnostics. Runtime module identity and matching cache/ZIP bytes are premises, not physical compiled-byte attestation or all algorithm/varint/cryptographic guarantees.", input, nil)
	if e.Error == "" && ctx.Err() == nil && multihashSourceReady(e.Source) {
		groups := [][]core.Verdict{{}, {}}
		for _, f := range multihashFixtures() {
			i := 0
			if f.Statement == multihashIDs[1] {
				i = 1
			}
			v, ok := e.Calls[f.Name]
			verdict := core.Error
			if ok && e.Errors[f.Name] == "" {
				verdict = multihashCallVerdict(f, v)
			}
			groups[i] = append(groups[i], verdict)
		}
		for i := range obs {
			obs[i].Verdict = core.Aggregate(groups[i])
			obs[i].Expected = "Literal header varint, length varint and digest order; decoded digest matches both expected and declared lengths"
		}
	}
	if ctx.Err() != nil {
		e.Error = ctx.Err().Error()
	}
	raw, _ := json.Marshal(e)
	for i := range obs {
		obs[i].Observed = string(raw)
	}
	return obs
}
func appendMultihashCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/multihash-component-operations", Profile: p.Name, Statements: multihashIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		source, ok := target.(IntegerSourceSubject)
		probe, ok1 := target.(MultihashSubject)
		q := multihashSourceRequest()
		input, _ := json.Marshal(q)
		if !ok || !ok1 {
			return libraryUnavailable(multihashIDs, core.NotSupported, "no selected source/component operations", string(input), nil)
		}
		e := multihashEvidence{Calls: map[string]MultihashResult{}, Errors: map[string]string{}}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			e.Error = err.Error()
			return judgeMultihash(ctx, e, string(input))
		}
		for _, f := range multihashFixtures() {
			v, err := probe.InspectMultihash(ctx, f.Request)
			e.Calls[f.Name] = v
			if err != nil {
				e.Errors[f.Name] = err.Error()
			}
		}
		return judgeMultihash(ctx, e, string(input))
	}})
}
