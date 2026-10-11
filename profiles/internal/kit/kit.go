// Package kit holds what the cases of the built-in profiles share: an
// observation recorder, the formats of the fixture files under
// profiles/<profile>/testdata, and generic case builders that turn those
// fixtures into cases. Each profile supplies its own fixtures, statement
// ids and version, so the profiles share code but no verdicts.
package kit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// Recorder collects the observations of one case run.
type Recorder struct {
	out []core.Observation
}

// Add records one observation.
func (r *Recorder) Add(o core.Observation) {
	r.out = append(r.out, o)
}

// Judge records, for each statement, PASS when ok and FAIL with the
// expected and observed values otherwise. note, when not empty, is kept as
// the observation's detail; cases use it to say that they judge a
// statement only partly.
func (r *Recorder) Judge(statements []string, input string, ok bool, expected, observed, note string) {
	for _, st := range statements {
		o := core.Observation{Statement: st, Input: input, Detail: note}
		if ok {
			o.Verdict = core.Pass
		} else {
			o.Verdict, o.Expected, o.Observed = core.Fail, expected, nonEmpty(observed)
		}
		r.Add(o)
	}
}

// All records the same verdict and detail for each statement.
func (r *Recorder) All(statements []string, v core.Verdict, input, detail string) {
	for _, st := range statements {
		r.Add(core.Observation{Statement: st, Verdict: v, Input: input, Detail: detail})
	}
}

// Observations returns what was recorded.
func (r *Recorder) Observations() []core.Observation {
	return r.out
}

// nonEmpty keeps a FAIL well formed when the observed value is empty.
func nonEmpty(s string) string {
	if s == "" {
		return "(nothing)"
	}
	return s
}

// Union returns the statement ids of the lists in order, without repeats.
func Union(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// Decode parses a fixture file into v, rejecting unknown fields so that a
// misspelled key cannot silently drop an input.
func Decode(name string, data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("kit: decode %s: %w", name, err)
	}
	return nil
}

// MustDecode is Decode for fixtures embedded in the binary, which the
// profile tests decode too; a broken embedded fixture is a build defect.
func MustDecode(name string, data []byte, v any) {
	if err := Decode(name, data, v); err != nil {
		panic(err)
	}
}

// MustRegistry parses an embedded fixture registry.
func MustRegistry(name string, data []byte) *fixtures.Registry {
	r, err := fixtures.Parse(data)
	if err != nil {
		panic(fmt.Errorf("kit: %s: %w", name, err))
	}
	return r
}

// LoadRegistry hands the registry to the subject. Cases that resolve call
// it first; a subject that cannot load it cannot be judged.
func LoadRegistry(s core.Subject, reg *fixtures.Registry) error {
	if err := s.(core.FixtureMethod).LoadFixtureRegistry(reg); err != nil {
		return fmt.Errorf("subject could not load the fixture registry: %w", err)
	}
	return nil
}

// RegistryCase wraps a run function that resolves: it loads the registry
// first and turns a load failure into ERROR for every statement.
func RegistryCase(reg *fixtures.Registry, statements []string, run func(ctx context.Context, s core.Subject) []core.Observation) func(context.Context, core.Subject) []core.Observation {
	return func(ctx context.Context, s core.Subject) []core.Observation {
		if err := LoadRegistry(s, reg); err != nil {
			var r Recorder
			r.All(statements, core.Error, "", err.Error())
			return r.Observations()
		}
		return run(ctx, s)
	}
}
