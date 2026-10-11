package report

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

// InputFor gathers what a report of res needs: the pinned sources of the
// profile's spec keys and every statement of those keys with its scope
// decision and level. Every command that runs a profile, including adapter commands
// in other modules, builds its report from it.
func InputFor(p core.Profile, res core.RunResult, inspectorRevision string) (Input, error) {
	scope, err := statements.Scope()
	if err != nil {
		return Input{}, err
	}
	in := Input{Result: res, InspectorRevision: inspectorRevision}
	for _, key := range p.SpecKeys {
		doc, err := statements.Load(key)
		if err != nil {
			return Input{}, err
		}
		in.Specs = append(in.Specs, Spec{Key: doc.Key, URL: doc.URL, Source: doc.Source, SHA256: doc.SHA256})
		for _, st := range doc.Statements {
			in.Statements = append(in.Statements, StatementRef{ID: st.ID, Scope: scope[st.ID].Scope, Level: st.Level})
		}
	}
	return in, nil
}
