// Package profiles keeps the registry of inspection profiles. Profiles are
// registered explicitly; importing a profile package registers nothing.
package profiles

import (
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/core10"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

// Registry holds profiles by name in registration order.
type Registry struct {
	byName map[string]core.Profile
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]core.Profile{}}
}

// Register validates p and adds it. A name may be registered once.
func (r *Registry) Register(p core.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if _, dup := r.byName[p.Name]; dup {
		return fmt.Errorf("profiles: %s is already registered", p.Name)
	}
	r.byName[p.Name] = p
	r.order = append(r.order, p.Name)
	return nil
}

// Lookup returns the profile with the given name.
func (r *Registry) Lookup(name string) (core.Profile, bool) {
	p, ok := r.byName[name]
	return p, ok
}

// Profiles returns the registered profiles in registration order.
func (r *Registry) Profiles() []core.Profile {
	out := make([]core.Profile, len(r.order))
	for i, name := range r.order {
		out[i] = r.byName[name]
	}
	return out
}

// Builtin returns the built-in profiles: did-core-1.0 and did-1.1.
func Builtin() []core.Profile {
	return []core.Profile{core10.Profile(), did11.Profile()}
}

// Default returns a registry with the built-in profiles registered.
func Default() (*Registry, error) {
	r := NewRegistry()
	for _, p := range Builtin() {
		if err := r.Register(p); err != nil {
			return nil, err
		}
	}
	return r, nil
}
