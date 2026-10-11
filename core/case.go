package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Observation is one judgment a case made about one statement.
type Observation struct {
	// Statement is the id of the statement judged; the case must name it.
	Statement string  `json:"statement"`
	Verdict   Verdict `json:"verdict"`
	// Input describes the input the case gave the subject.
	Input string `json:"input,omitempty"`
	// Expected is what the statement requires; Observed is what the subject
	// did. Both are set for FAIL.
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
	// Detail explains NOT_SUPPORTED, NOT_APPLICABLE and ERROR verdicts.
	Detail string `json:"detail,omitempty"`
}

// Case is one check of one or more statements under one profile.
type Case struct {
	// ID is stable across releases, e.g. "did11/consumer/media-type-decides".
	ID      string
	Profile string
	// Statements are the ids of the statements the case judges.
	Statements []string
	// Needs are the capabilities the case uses.
	Needs []Capability
	// Run performs the check. It reports at least one observation, each for
	// a statement in Statements.
	Run func(ctx context.Context, s Subject) []Observation
}

// Validate checks that the case is well formed.
func (c Case) Validate() error {
	var errs []error
	if strings.TrimSpace(c.ID) == "" {
		errs = append(errs, errors.New("empty id"))
	}
	if c.Profile == "" {
		errs = append(errs, errors.New("empty profile"))
	}
	if len(c.Statements) == 0 {
		errs = append(errs, errors.New("names no statement"))
	}
	seen := map[string]bool{}
	for _, st := range c.Statements {
		if st == "" {
			errs = append(errs, errors.New("empty statement id"))
		}
		if seen[st] {
			errs = append(errs, fmt.Errorf("statement %s named twice", st))
		}
		seen[st] = true
	}
	for _, n := range c.Needs {
		if !n.Valid() {
			errs = append(errs, fmt.Errorf("unknown capability %q", n))
		}
	}
	if c.Run == nil {
		errs = append(errs, errors.New("no Run function"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("case %q: %w", c.ID, errors.Join(errs...))
	}
	return nil
}

// names reports whether the case names statement id.
func (c Case) names(id string) bool {
	return slices.Contains(c.Statements, id)
}

// Profile is one set of pinned publications a subject is inspected against,
// with the cases that judge their statements.
type Profile struct {
	// Name is the profile name, e.g. "did-1.1".
	Name string
	// Title describes the profile.
	Title string
	// SpecKeys are the spec keys of the pinned publications.
	SpecKeys []string
	// Cases judge statements of those publications.
	Cases []Case
}

// Validate checks that the profile and its cases are well formed: case ids
// are unique, every case belongs to the profile, and every statement id a
// case names has one of the profile's spec keys.
func (p Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("profile: empty name")
	}
	if len(p.SpecKeys) == 0 {
		return fmt.Errorf("profile %s: no spec keys", p.Name)
	}
	ids := map[string]bool{}
	for _, c := range p.Cases {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("profile %s: %w", p.Name, err)
		}
		if c.Profile != p.Name {
			return fmt.Errorf("profile %s: case %s belongs to profile %s", p.Name, c.ID, c.Profile)
		}
		if ids[c.ID] {
			return fmt.Errorf("profile %s: duplicate case id %s", p.Name, c.ID)
		}
		ids[c.ID] = true
		for _, st := range c.Statements {
			if !p.hasSpecKey(st) {
				return fmt.Errorf("profile %s: case %s names %s, which is not in a spec of the profile", p.Name, c.ID, st)
			}
		}
	}
	return nil
}

func (p Profile) hasSpecKey(statementID string) bool {
	key, _, ok := strings.Cut(statementID, "#")
	return ok && slices.Contains(p.SpecKeys, key)
}
