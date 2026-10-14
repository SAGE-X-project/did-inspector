package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"time"
)

//go:embed value_cases.json
var libraryValueBytes []byte

type valueVector struct {
	Valid bool            `json:"valid"`
	Input json.RawMessage `json:"input"`
}
type valueFixture struct {
	Field      string        `json:"field"`
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	Statements []string      `json:"statements"`
	Permission bool          `json:"permission"`
	Values     []valueVector `json:"values"`
}

func valueFixtures() []valueFixture {
	var out []valueFixture
	_ = json.Unmarshal(libraryValueBytes, &out)
	return out
}
func valueRequest(f valueFixture, v valueVector) LibraryValueRequest {
	return LibraryValueRequest{Kind: f.Kind, Input: append([]byte(nil), v.Input...), Subject: policyDID}
}
func valueActor(kind string) (string, string, string) {
	prefix := "github.com/sage-x-project/did-go/resolution.ResolutionMetadata"
	validation := "Validate"
	if kind == "document-metadata" {
		prefix = "github.com/sage-x-project/did-go/document.Metadata"
		validation = "Check"
	}
	if kind == "resolution-options" {
		prefix = "github.com/sage-x-project/did-go/resolution.ResolutionOptions"
	}
	return prefix + ".UnmarshalJSON", prefix + "." + validation, prefix + ".MarshalJSON"
}
func judgeLibraryValues(f valueFixture, values []LibraryValueResult, input string) []core.Observation {
	out := libraryUnavailable(f.Statements, core.Error, "Actual selected typed library reader, validator and serializer only. Independent literal valid/invalid expectations are not obtained from the subject validator or error annotations. Date syntax, ASCII/DID container format and declared structural proof maps only; no Create/Update history, method-issued equivalence, guaranteed canonical identifiers, cryptographic proof validity, SAGE Source production or whole standard conformance. OPTIONAL fields are capabilities, not mandatory feature obligations.", input, values)
	if len(values) != len(f.Values) {
		return out
	}
	known := false
	for _, candidate := range valueFixtures() {
		a, _ := json.Marshal(candidate)
		b, _ := json.Marshal(f)
		if bytes.Equal(a, b) {
			known = true
		}
	}
	if !known {
		return out
	}
	verdict := core.Pass
	reader, validator, writer := valueActor(f.Kind)
	for i, q := range f.Values {
		actual := values[i]
		request := valueRequest(f, q)
		if actual.Request.Kind != request.Kind || actual.Request.Subject != request.Subject || !bytes.Equal(actual.Request.Input, request.Input) || actual.Reader != reader {
			return out
		}
		if actual.ReadError != "" && (actual.Validator != "" || actual.Writer != "" || len(actual.Output) > 0) {
			return out
		}
		if actual.ValidationError != "" && (actual.Writer != "" || len(actual.Output) > 0) {
			return out
		}
		if actual.WriteError != "" {
			return out
		}
		if q.Valid {
			if actual.ReadError != "" || actual.ValidationError != "" || actual.WriteError != "" {
				if i == 0 {
					return out
				}
				verdict = core.NotSupported
				continue
			}
			if actual.Validator != validator || actual.Writer != writer {
				return out
			}
			got, e := core.ParseJSON(actual.Output)
			want, ee := core.ParseJSON(q.Input)
			if e != nil || ee != nil {
				return out
			}
			if !equalObserved(got, want, "metadata") {
				if f.Permission {
					verdict = core.NotSupported
				} else {
					if !valueOutputConforms(f, actual.Output) {
						verdict = core.Fail
					} else {
						return out
					}
				}
			}
		} else {
			if actual.ReadError != "" {
				if actual.Validator != "" || actual.Writer != "" || len(actual.Output) > 0 {
					return out
				}
				continue
			}
			if actual.Validator != validator {
				return out
			}
			if actual.ValidationError != "" {
				if actual.Writer != "" || len(actual.Output) > 0 {
					return out
				}
				continue
			}
			if actual.Writer != writer || actual.WriteError != "" {
				return out
			}
			if !valueOutputConforms(f, actual.Output) {
				verdict = core.Fail
			}
		}
	}
	for i := range out {
		out[i].Verdict = verdict
		out[i].Expected = "Literal valid inputs preserved; independent malformed date/ASCII/DID/map controls refused; optional absence and presence supported"
	}
	return out
}
func appendLibraryValueCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range valueFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/remaining-value-%s", p.Name, f.Name), Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := []LibraryValueResult{}
			s, ok := target.(LibraryValueSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no typed library value observer", string(input), out)
			}
			for _, v := range f.Values {
				actual, e := s.InspectLibraryValue(ctx, valueRequest(f, v))
				out = append(out, actual)
				if e != nil {
					return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
				}
			}
			return judgeLibraryValues(f, out, string(input))
		}})
	}
}

func valueOutputConforms(f valueFixture, b []byte) bool {
	root, e := core.ParseJSON(b)
	if e != nil || root.Kind != core.KindObject || len(checks.DuplicateMembers(root)) > 0 {
		return false
	}
	v, ok := root.Get(f.Field)
	if !ok {
		return true
	} // Conditional fields need not be emitted.
	switch f.Field {
	case "created", "updated", "nextUpdate":
		if v.Kind != core.KindString || len(v.Str) != 20 || !strings.HasSuffix(v.Str, "Z") {
			return false
		}
		_, e := time.Parse(time.RFC3339, v.Str)
		return e == nil
	case "nextVersionId":
		return v.Kind == core.KindString && checks.IsASCII(v.Str)
	case "canonicalId":
		return v.Kind == core.KindString && checks.IsDID(v.Str)
	case "equivalentId":
		if v.Kind != core.KindArray {
			return false
		}
		for _, item := range v.Array {
			if item.Kind != core.KindString || !checks.IsDID(item.Str) {
				return false
			}
		}
		return true
	case "proof":
		if v.Kind != core.KindArray {
			return false
		}
		for _, item := range v.Array {
			if item.Kind != core.KindObject {
				return false
			}
		}
		return true
	}
	return false
}
