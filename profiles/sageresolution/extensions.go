package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

// MultibaseExtensionSubject executes a bounded additional encoding directly in
// the original component; it is distinct from the u-only allocation observer.
type MultibaseExtensionSubject interface {
	InspectMultibaseExtension(context.Context, CapacityRequest) (CapacityResult, error)
}

const extensionBaseID = "cid10#multibase-0.1"
const extensionHashID = "cid10#multihash.1"
const applicationID = "res10-crd20261001#dereferencing-algorithm-resource.48"

// ApplicationResourceCapture records the actual original dispatcher callback
// and its supplied result separately from the final dereferencing result.
type ApplicationResourceCapture struct {
	Input    ResourceHandlerCapture `json:"input"`
	Handled  bool                   `json:"handled"`
	Returned Result                 `json:"returned"`
}

func extensionBaseRequests() []CapacityRequest {
	out := []CapacityRequest{}
	for i, h := range []byte{'z', 'u', 'f'} {
		encoded := []string{"z1ftS", "uAf7_", "f0001feff"}[i]
		out = append(out, CapacityRequest{Operation: "encode", Header: h, Data: []byte{0, 1, 254, 255}}, CapacityRequest{Operation: "decode", Encoded: encoded})
	}
	return out
}
func extensionHashRequests() []MultihashRequest {
	out := []MultihashRequest{}
	for i, code := range []uint64{0x12, 0x20, 0x16, 0x15, 0x13} {
		n := []int{32, 48, 32, 48, 64}[i]
		digest := make([]byte, n)
		for j := range digest {
			digest[j] = byte(j)
		}
		encoded := append([]byte{byte(code), byte(n)}, digest...)
		out = append(out, MultihashRequest{Operation: "encode", Code: code, Digest: digest}, MultihashRequest{Operation: "decode", Encoded: encoded})
	}
	return out
}
func extensionObserver(v ComponentObserver) bool {
	if v.ReplacementVersion == "" {
		v.ReplacementVersion = "(devel)"
	}
	return v == (ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", ReplacementVersion: "(devel)", Compiler: "go1.26.8"})
}
func extensionBaseWitness(q CapacityRequest, v CapacityResult) bool {
	op := "EncodeMultibase"
	if q.Operation == "decode" {
		op = "DecodeMultibase"
	}
	return reflect.DeepEqual(q, v.Request) && extensionObserver(v.Observer) && v.Role == MultihashRole && v.Operation == IntegerSourceModule+"/internal/multiformats."+op
}
func extensionHashWitness(q MultihashRequest, v MultihashResult) bool {
	op := "EncodeMultihash"
	if q.Operation == "decode" {
		op = "DecodeMultihash"
	}
	return reflect.DeepEqual(q, v.Request) && extensionObserver(v.Observer) && v.Role == MultihashRole && v.Operation == IntegerSourceModule+"/internal/multiformats."+op
}
func extensionBaseOutput(i int, v CapacityResult) bool {
	qs := extensionBaseRequests()
	if i%2 == 0 {
		return v.Encoded == qs[i+1].Encoded
	}
	return v.Header == qs[i-1].Header && bytes.Equal(v.Data, qs[i-1].Data)
}
func extensionHashOutput(i int, v MultihashResult) bool {
	qs := extensionHashRequests()
	if i%2 == 0 {
		return bytes.Equal(v.Encoded, qs[i+1].Encoded)
	}
	return v.Code == qs[i-1].Code && bytes.Equal(v.Digest, qs[i-1].Digest)
}

type extensionEvidence struct {
	Source    IntegerSourceResult `json:"source"`
	Base      []CapacityResult    `json:"multibase"`
	Hash      []MultihashResult   `json:"multihash"`
	Error     string              `json:"capture_error,omitempty"`
	BaseError string              `json:"multibase_capture_error,omitempty"`
	HashError string              `json:"multihash_capture_error,omitempty"`
}

func judgeExtensions(e extensionEvidence, input string) []core.Observation {
	out := libraryUnavailable([]string{extensionBaseID, extensionHashID}, core.Error, "Selected f/base16 and 0x13/64-octet multihash encode/decode capabilities in the original component through the separately identified Inspector probe. Four CID hash codes and both CID base alphabets are controls. Only explicit original unsupported declarations yield NOT_SUPPORTED; controls, source, attribution or unexpected outputs yield ERROR. No claim about every extension, hashing computation, cryptographic security or SAGE production use.", input, e)
	bq, hq := extensionBaseRequests(), extensionHashRequests()
	if e.Error != "" || !multihashSourceReady(e.Source) {
		return out
	}
	judgeBase := func() core.Verdict {
		if e.BaseError != "" || len(e.Base) != len(bq) {
			return core.Error
		}
		verdict := core.Pass
		for i, v := range e.Base {
			if !extensionBaseWitness(bq[i], v) {
				return core.Error
			}
			if i < 4 {
				if v.Error != "" || !extensionBaseOutput(i, v) {
					return core.Error
				}
				continue
			}
			if v.Error == "multiformats: header 'f' is not defined by CID 1.0" {
				if v.Encoded != "" || len(v.Data) != 0 || (i%2 == 0 && v.Header != 0) || (i%2 == 1 && v.Header != 'f') {
					return core.Error
				}
				verdict = core.NotSupported
				continue
			}
			if v.Error != "" || !extensionBaseOutput(i, v) {
				return core.Error
			}
		}
		return verdict
	}
	judgeHash := func() core.Verdict {
		if e.HashError != "" || len(e.Hash) != len(hq) {
			return core.Error
		}
		verdict := core.Pass
		for i, v := range e.Hash {
			if !extensionHashWitness(hq[i], v) {
				return core.Error
			}
			if i < 8 {
				if v.Error != "" || !extensionHashOutput(i, v) {
					return core.Error
				}
				continue
			}
			if v.Error == "multiformats: Multihash header 0x13 is not defined by CID 1.0" {
				if len(v.Encoded) != 0 || len(v.Digest) != 0 || v.Code != 0 {
					return core.Error
				}
				verdict = core.NotSupported
				continue
			}
			if v.Error != "" || !extensionHashOutput(i, v) {
				return core.Error
			}
		}
		return verdict
	}
	out[0].Verdict = judgeBase()
	out[1].Verdict = judgeHash()
	return out
}
func appendExtensionCodecCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/extension-codecs", Profile: p.Name, Statements: []string{extensionBaseID, extensionHashID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := multihashSourceRequest()
		input, _ := json.Marshal(q)
		source, a := target.(IntegerSourceSubject)
		base, b := target.(MultibaseExtensionSubject)
		hash, c := target.(MultihashSubject)
		if !a {
			return libraryUnavailable([]string{extensionBaseID, extensionHashID}, core.Error, "missing selected original component observer", string(input), nil)
		}
		e := extensionEvidence{}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			e.Error = err.Error()
			return judgeExtensions(e, string(input))
		}
		if !b {
			e.BaseError = "missing selected original multibase observer"
		} else {
			for _, req := range extensionBaseRequests() {
				v, err := base.InspectMultibaseExtension(ctx, req)
				e.Base = append(e.Base, v)
				if err != nil {
					e.BaseError = err.Error()
					break
				}
			}
		}
		if !c {
			e.HashError = "missing selected original multihash observer"
		} else {
			for _, req := range extensionHashRequests() {
				v, err := hash.InspectMultihash(ctx, req)
				e.Hash = append(e.Hash, v)
				if err != nil {
					e.HashError = err.Error()
					break
				}
			}
		}
		return judgeExtensions(e, string(input))
	}})
}
