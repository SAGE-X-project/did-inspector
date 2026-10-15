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

var capacityIDs = []string{"cid10#base-encode.4", "cid10#base-decode.5"}

const capacityCase = "did-1.1/sage-resolution/capacity-u64-component"

type CapacityRequest struct {
	Operation string `json:"operation"`
	Header    byte   `json:"header"`
	Data      []byte `json:"data"`
	Encoded   string `json:"encoded"`
}
type CapacityResult struct {
	Request   CapacityRequest   `json:"request"`
	Observer  ComponentObserver `json:"observer"`
	Operation string            `json:"operation"`
	Role      string            `json:"role"`
	Encoded   string            `json:"encoded"`
	Header    byte              `json:"header"`
	Data      []byte            `json:"data"`
	Error     string            `json:"error,omitempty"`
}
type CapacitySubject interface {
	core.Subject
	InspectCapacity(context.Context, CapacityRequest) (CapacityResult, error)
}
type capacityFixture struct {
	Name    string          `json:"name"`
	Request CapacityRequest `json:"request"`
	Encoded string          `json:"expected_encoded"`
	Data    []byte          `json:"expected_data"`
}
type capacityEvidence struct {
	Source       IntegerSourceResult       `json:"source"`
	Audit        sourcearith.CapacityAudit `json:"audit"`
	Calls        []CapacityResult          `json:"calls"`
	Error        string                    `json:"analysis_error,omitempty"`
	Compiler     string                    `json:"type_checker_compiler"`
	Architecture string                    `json:"type_checker_architecture"`
}

//go:embed capacity.json
var capacityBytes []byte

//go:embed capacity_witness.json
var capacityWitness []byte

func capacityFixtures() []capacityFixture {
	out := []capacityFixture{}
	_ = json.Unmarshal(capacityBytes, &out)
	return out
}
func capacityAuditVerdict(a sourcearith.CapacityAudit, index int) core.Verdict {
	var witness sourcearith.CapacityAudit
	if json.Unmarshal(capacityWitness, &witness) != nil || !reflect.DeepEqual(a.Frames, witness.Frames) || len(a.Unknown) != 0 || len(a.Steps) != 2 || index < 0 || index >= 2 {
		return core.Error
	}
	if !a.Steps[index].Correct {
		return core.Error
	}
	return core.Pass
}
func capacityCallVerdict(f capacityFixture, v CapacityResult) core.Verdict {
	o := v.Observer
	if o.ReplacementVersion == "" {
		o.ReplacementVersion = "(devel)"
	}
	operation := "EncodeMultibase"
	if f.Request.Operation == "decode" {
		operation = "DecodeMultibase"
	}
	if o != (ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", ReplacementVersion: "(devel)", Compiler: "go1.26.8"}) || !reflect.DeepEqual(v.Request, f.Request) || v.Operation != IntegerSourceModule+"/internal/multiformats."+operation || v.Role != MultihashRole {
		return core.Error
	}
	if v.Error != "" {
		return core.Error
	}
	if f.Request.Operation == "encode" {
		if v.Encoded != f.Encoded {
			return core.Error
		}
	} else if v.Header != 'u' || !bytes.Equal(v.Data, f.Data) {
		return core.Error
	}
	return core.Pass
}
func judgeCapacity(ctx context.Context, e capacityEvidence, input string) []core.Observation {
	obs := libraryUnavailable(capacityIDs, core.Error, "Pinned original u/64 component actor, independently typed fixed-source allocation phases and fresh direct component calls. For base64, log(256)/log(64)=8/6 and its inverse=6/8 exactly; Go truncation plus one matches the reference under the stated bounded stable-input domain, with zero-initialized integer storage. Only inputs up to 4096 bytes/characters and successful allocation are claimed. Not RFC4648 helpers, public Multikey z capacity, all runtime executions, complete algorithm equivalence, conflicting encode.13/decode.16, or compiled-byte attestation. Outputs corroborate caller reachability, not the internal size proof.", input, nil)
	if e.Error == "" && ctx.Err() == nil && multihashSourceReady(e.Source) && e.Compiler == runtime.Version() && runtime.Version() == e.Source.Compiler && len(e.Calls) == len(capacityFixtures()) {
		program := sourcearith.NewProgram(ctx, IntegerSourceModule, e.Source.Files)
		if _, err := program.Import(IntegerSourceModule + "/internal/multiformats"); err != nil {
			e.Error = err.Error()
		} else {
			e.Audit = program.CapacityAudit()
			good := true
			for i, f := range capacityFixtures() {
				if capacityCallVerdict(f, e.Calls[i]) != core.Pass {
					good = false
				}
			}
			if good {
				for i := range obs {
					obs[i].Verdict = capacityAuditVerdict(e.Audit, i)
					obs[i].Expected = "Zero-initialized selected buffer uses floor(n*8/6)+1 or floor(n*6/8)+1 with the actual non-leading-zero input length, under the bounded u/64 branch"
				}
			}
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
func appendCapacityCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: capacityCase, Profile: p.Name, Statements: capacityIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := multihashSourceRequest()
		input, _ := json.Marshal(q)
		s, ok := target.(IntegerSourceSubject)
		c, ok1 := target.(CapacitySubject)
		e := capacityEvidence{Calls: []CapacityResult{}, Compiler: runtime.Version(), Architecture: runtime.GOARCH}
		if !ok || !ok1 {
			return libraryUnavailable(capacityIDs, core.NotSupported, "requires pinned source and direct u/64 component observer", string(input), e)
		}
		var err error
		e.Source, err = s.InspectIntegerSource(ctx, q)
		if err != nil {
			e.Error = err.Error()
			return judgeCapacity(ctx, e, string(input))
		}
		for _, f := range capacityFixtures() {
			v, err := c.InspectCapacity(ctx, f.Request)
			e.Calls = append(e.Calls, v)
			if err != nil {
				e.Error = err.Error()
				break
			}
		}
		return judgeCapacity(ctx, e, string(input))
	}})
}
