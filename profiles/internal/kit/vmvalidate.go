package kit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// VMVector is one standalone verification method a verification method
// validator is given, with the property under judgment and whether the
// value of that property conforms.
type VMVector struct {
	Name   string
	Method core.DocumentJSON
	// Property is the member whose value the vector judges, for example
	// "secretKeyMultibase".
	Property string
	// Valid reports whether the property's value conforms; Why says why an
	// invalid one does not.
	Valid bool
	Why   string
	// Statements are the statements the vector judges.
	Statements []string
}

// VMGroup becomes one case.
type VMGroup struct {
	// Case is the case id suffix.
	Case    string
	Vectors []VMVector
	// Partial says what the group does not judge of its statements.
	Partial string
}

// Statements returns the statements of all vectors without repeats.
func (g VMGroup) Statements() []string {
	lists := make([][]string, len(g.Vectors))
	for i, v := range g.Vectors {
		lists[i] = v.Statements
	}
	return Union(lists...)
}

// VMValidatorCases returns one case per group. A vector is judged by the
// findings that concern its property: a finding whose path is the
// property's JSON Pointer, lies below it, or is the whole method (""). A
// conforming value must draw no such finding; a non-conforming one at
// least one. Findings about other members are not the vector's business.
func VMValidatorCases(profile, version string, groups []VMGroup) []core.Case {
	out := make([]core.Case, 0, len(groups))
	for _, g := range groups {
		sts := g.Statements()
		out = append(out, core.Case{
			ID:         profile + "/verification-method/" + g.Case,
			Profile:    profile,
			Statements: sts,
			Needs:      []core.Capability{core.CapVerificationMethodValidator},
			Run: func(_ context.Context, s core.Subject) []core.Observation {
				v := s.(core.VerificationMethodValidator)
				var r Recorder
				for _, vec := range g.Vectors {
					judgeVMVector(&r, v, vec, version, g.Partial)
				}
				return r.Observations()
			},
		})
	}
	return out
}

func judgeVMVector(r *Recorder, v core.VerificationMethodValidator, vec VMVector, version, partial string) {
	input := vec.Name + ": " + checks.Compact(vec.Method.Value())
	findings, err := v.ValidateVerificationMethod(vec.Method, version)
	if err != nil {
		r.All(vec.Statements, core.Error, input, "the validator failed: "+err.Error())
		return
	}
	concerning := findingsAt(findings, "/"+vec.Property)
	if vec.Valid {
		r.Judge(vec.Statements, input, len(concerning) == 0, "no finding about "+vec.Property, describeFindings(concerning), partial)
		return
	}
	r.Judge(vec.Statements, input, len(concerning) > 0, "a finding about "+vec.Property+" ("+vec.Why+")", describeFindings(findings), partial)
}

// findingsAt returns the findings at pointer, below it, or about the whole
// object.
func findingsAt(fs []core.Finding, pointer string) []core.Finding {
	var out []core.Finding
	for _, f := range fs {
		if f.Path == "" || f.Path == pointer || strings.HasPrefix(f.Path, pointer+"/") {
			out = append(out, f)
		}
	}
	return out
}

func describeFindings(fs []core.Finding) string {
	if len(fs) == 0 {
		return "no finding"
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = fmt.Sprintf("%s at %q: %s", f.Code, f.Path, f.Message)
	}
	return strings.Join(parts, "; ")
}

// ValidateVMGroups checks verification method groups: every group has a
// case id and vectors, and every vector a name, a property, statements
// and, when invalid, a reason.
func ValidateVMGroups(groups []VMGroup) error {
	var errs []error
	for i, g := range groups {
		where := fmt.Sprintf("group %d (%s)", i, g.Case)
		if g.Case == "" || len(g.Vectors) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs case and vectors", where))
		}
		for _, v := range g.Vectors {
			if v.Name == "" || v.Property == "" || len(v.Statements) == 0 {
				errs = append(errs, fmt.Errorf("%s: vector %q needs name, property and statements", where, v.Name))
			}
			if !v.Valid && v.Why == "" {
				errs = append(errs, fmt.Errorf("%s: invalid vector %q has no why", where, v.Name))
			}
		}
	}
	return errors.Join(errs...)
}
