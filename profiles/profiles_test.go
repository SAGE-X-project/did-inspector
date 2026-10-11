package profiles

import (
	"context"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

func TestDefault(t *testing.T) {
	r, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	ps := r.Profiles()
	if len(ps) != 2 || ps[0].Name != "did-core-1.0" || ps[1].Name != "did-1.1" {
		t.Fatalf("profiles = %+v", ps)
	}
	if _, ok := r.Lookup("did-1.1"); !ok {
		t.Fatal("did-1.1 not found")
	}
	if _, ok := r.Lookup("did-9"); ok {
		t.Fatal("unknown profile found")
	}
}

func TestRegisterErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(core.Profile{}); err == nil {
		t.Error("invalid profile registered")
	}
	p := core.Profile{Name: "x", SpecKeys: []string{"k"}}
	if err := r.Register(p); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(p); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("duplicate err = %v", err)
	}
}

// TestBuiltinProfilesMatchStatements checks that every spec key of a
// built-in profile is pinned, every statement a case names was extracted,
// every statement scoped "checked" is named by a case, and every statement
// a case names is scoped "checked".
func TestBuiltinProfilesMatchStatements(t *testing.T) {
	known := map[string]bool{}
	docs, err := statements.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		for _, st := range d.Statements {
			known[st.ID] = true
		}
	}
	named := map[string]bool{}
	for _, p := range Builtin() {
		for _, k := range p.SpecKeys {
			if _, err := statements.Load(k); err != nil {
				t.Errorf("%s: %v", p.Name, err)
			}
		}
		for _, c := range p.Cases {
			for _, st := range c.Statements {
				named[st] = true
				if !known[st] {
					t.Errorf("%s: case %s names unknown statement %s", p.Name, c.ID, st)
				}
			}
		}
	}
	scope, err := statements.Scope()
	if err != nil {
		t.Fatal(err)
	}
	for id, d := range scope {
		if d.Scope == statements.ScopeChecked && !named[id] {
			t.Errorf("%s is scoped checked but no case names it", id)
		}
	}
	for id := range named {
		if scope[id].Scope != statements.ScopeChecked {
			t.Errorf("%s is named by a case but scoped %q", id, scope[id].Scope)
		}
	}
}

func TestBuiltinProfilesRunEmpty(t *testing.T) {
	r, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Profiles() {
		res, err := core.Runner{}.Run(context.Background(), p, bare{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Cases) != len(p.Cases) {
			t.Errorf("%s: ran %d cases of %d", p.Name, len(res.Cases), len(p.Cases))
		}
	}
}

type bare struct{}

func (bare) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "bare"} }
func (bare) Supports(string, core.Capability) bool { return false }
