// Package core10 is the did-core-1.0 profile: DID Core 1.0 (W3C
// Recommendation 19 July 2022), including the resolution functions of its §7.
package core10

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

// Name is the profile name.
const Name = "did-core-1.0"

// Profile returns the profile with its cases.
func Profile() core.Profile {
	return core.Profile{
		Name:     Name,
		Title:    "DID Core 1.0 (W3C Recommendation 2022-07-19), including the resolution functions of §7",
		SpecKeys: []string{statements.KeyCore10},
		Cases:    cases(),
	}
}

// cases returns the profile's cases. Cases are added statement by statement.
func cases() []core.Case {
	return nil
}
