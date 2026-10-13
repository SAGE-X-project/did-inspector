package sageprojection

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/core10"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

//go:embed records.json
var recordBytes []byte

// Fixtures exposes fresh independent records for adapter runtime controls.
func Fixtures() ([]Record, error) {
	sum := sha256.Sum256(recordBytes)
	if hex.EncodeToString(sum[:]) != fixtureHash {
		return nil, fmt.Errorf("SAGE record fixture drift")
	}
	var rows []Record
	if err := json.Unmarshal(recordBytes, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// Profile selects the pinned publications but only projection-output cases.
// All publication statements without these cases remain NOT_RUN. The normal
// did-go profiles and their cases remain unchanged.
func Profile(name string) (core.Profile, error) {
	var p core.Profile
	switch name {
	case core10.Name:
		p = core10.Profile()
	case did11.Name:
		p = did11.Profile()
	default:
		return p, fmt.Errorf("unknown projection profile %q", name)
	}
	rows, err := Fixtures()
	if err != nil {
		return p, err
	}
	p.Title += "; SAGE produced-document observations only"
	p.Cases = nil
	for i, r := range rows {
		rules := rulesFor(name)
		ids := make([]string, len(rules))
		for j, rule := range rules {
			ids[j] = rule.id
		}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-projection/record-%d", name, i), Profile: name, Statements: ids, Run: func(ctx context.Context, s core.Subject) []core.Observation {
			subject, ok := s.(Subject)
			if !ok {
				return observations(ids, core.NotSupported, "subject has no record projection operation")
			}
			version := "1.0"
			if name == did11.Name {
				version = "1.1"
			}
			out, err := subject.Project(ctx, r, version)
			if err != nil {
				return observations(ids, core.Error, "adapter execution: "+err.Error())
			}
			if out.ProblemCode != "" {
				return observations(ids, core.Error, "valid fixture refused: "+out.ProblemCode)
			}
			input, _ := json.Marshal(r)
			return judge(out, name, rules, string(input))
		}})
	}
	return p, p.Validate()
}
func observations(ids []string, v core.Verdict, detail string) []core.Observation {
	out := make([]core.Observation, len(ids))
	for i, id := range ids {
		out[i] = core.Observation{Statement: id, Verdict: v, Detail: detail}
	}
	return out
}
