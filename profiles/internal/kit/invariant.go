package kit

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// Invariant is a rule every result of a function must satisfy, such as the
// format of a metadata property wherever it appears.
type Invariant struct {
	Statement string
	// Partial says what the invariant does not judge of its statement.
	Partial string
	// Check reports whether the rule concerns the outcome and, if so,
	// whether the outcome satisfies it.
	Check func(o Outcome) (applies, ok bool, expected, observed string)
}

// InvariantCase returns a case that makes every call of the scenarios and
// probes and judges each invariant on each outcome it concerns. An invariant that no
// outcome concerns is NOT_APPLICABLE. All scenarios must use functions of
// the same capability.
func InvariantCase(id, profile string, reg *fixtures.Registry, invs []Invariant, f ScenarioFile) core.Case {
	sts := make([]string, len(invs))
	for i, inv := range invs {
		sts[i] = inv.Statement
	}
	var cp core.Capability
	if len(f.Scenarios) > 0 {
		cp, _ = FunctionCapability(f.Scenarios[0].Function)
	}
	return core.Case{
		ID:         id,
		Profile:    profile,
		Statements: sts,
		Needs:      []core.Capability{core.CapFixtureMethod, cp},
		Run: RegistryCase(reg, sts, func(ctx context.Context, s core.Subject) []core.Observation {
			var r Recorder
			judged := make([]bool, len(invs))
			for _, sc := range f.calls() {
				o := Call(ctx, s, sc.Function, sc.Input, CloneOptions(sc.Options))
				if o.Err != nil {
					continue
				}
				for i, inv := range invs {
					applies, ok, exp, obs := inv.Check(o)
					if !applies {
						continue
					}
					judged[i] = true
					r.Judge([]string{inv.Statement}, describeCall(sc), ok, exp, obs, inv.Partial)
				}
			}
			for i, inv := range invs {
				if !judged[i] {
					r.All([]string{inv.Statement}, core.NotApplicable, "", "no result of the scenarios concerned this statement")
				}
			}
			return r.Observations()
		}),
	}
}

// MemberRule returns an invariant on one property of a metadata structure
// of an outcome: it applies when the property is present.
func MemberRule(statement, partial string, pick func(Outcome) core.DocumentJSON, name, expected string, valid func(core.Value) bool) Invariant {
	return Invariant{
		Statement: statement,
		Partial:   partial,
		Check: func(o Outcome) (bool, bool, string, string) {
			v, ok := pick(o).Get(name)
			if !ok {
				return false, false, "", ""
			}
			return true, valid(v), name + ": " + expected, name + " " + checks.Compact(v)
		},
	}
}

// PickMetadata selects the resolution or dereferencing metadata.
func PickMetadata(o Outcome) core.DocumentJSON { return o.Metadata }

// PickContentMetadata selects the DID document or content metadata.
func PickContentMetadata(o Outcome) core.DocumentJSON { return o.ContentMetadata }

// IsDatetime reports whether v is a string in the normalized datetime form
// of DID Core 1.0 §7.1.3 and DID Resolution §3.1.
func IsDatetime(v core.Value) bool {
	return v.Kind == core.KindString && checks.CheckDatetime(v.Str) == nil
}

// IsASCIIString reports whether v is an ASCII string.
func IsASCIIString(v core.Value) bool {
	return v.Kind == core.KindString && checks.IsASCII(v.Str)
}

// IsDIDString reports whether v is a string that conforms to the did rule.
func IsDIDString(v core.Value) bool {
	return v.Kind == core.KindString && checks.IsDID(v.Str)
}

// IsSetOf reports whether v is an array of distinct items that each
// satisfy item.
func IsSetOf(v core.Value, item func(core.Value) bool) bool {
	if v.Kind != core.KindArray {
		return false
	}
	for i, x := range v.Array {
		if !item(x) {
			return false
		}
		for _, y := range v.Array[:i] {
			if eq, _ := checks.EqualJSON(x, y); eq {
				return false
			}
		}
	}
	return true
}

// IsMap reports whether v is a JSON object.
func IsMap(v core.Value) bool { return v.Kind == core.KindObject }

// SameMethod returns a predicate for DIDs of the method of the outcome's
// input.
func SameMethod(o Outcome) func(core.Value) bool {
	want := ""
	if u, err := checks.ParseDIDURL(o.Input); err == nil {
		want = u.DID.Method
	}
	return func(v core.Value) bool {
		d, err := checks.ParseDID(v.Str)
		return v.Kind == core.KindString && err == nil && d.Method == want
	}
}

// MethodRule returns an invariant that every DID in a property of the
// content metadata is of the method of the resolved DID.
func MethodRule(statement, name string, set bool) Invariant {
	return Invariant{
		Statement: statement,
		Check: func(o Outcome) (bool, bool, string, string) {
			v, ok := o.ContentMetadata.Get(name)
			if !ok {
				return false, false, "", ""
			}
			same := SameMethod(o)
			items := []core.Value{v}
			if set {
				items = v.Array
			}
			for _, x := range items {
				if !same(x) {
					return true, false, fmt.Sprintf("%s: DIDs of the method of %s", name, o.Input), name + " " + checks.Compact(v)
				}
			}
			return true, true, "", ""
		},
	}
}
