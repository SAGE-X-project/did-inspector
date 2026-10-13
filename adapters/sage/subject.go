// Package sage translates public fixture records to the actual advanced/sage
// projection API. It never uses subject validation as an inspection oracle.
package sage

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime/debug"

	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const ModulePath = "github.com/sage-x-project/did-go/advanced/sage"
const Version = "v0.0.0-20261012020818-2ef282b40ccf"

// Subject exposes record projection only, not general did-go capabilities.
type Subject struct{ info core.SubjectInfo }

// New identifies the pinned subject from actual binary build information.
func New() (*Subject, error) { return identify(debug.ReadBuildInfo) }
func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing subject build identity")
	}
	rootOK, sageOK := false, false
	for _, m := range bi.Deps {
		if m.Path == ModulePath {
			sageOK = m.Version == Version && m.Replace == nil
		}
		if m.Path == "github.com/sage-x-project/did-go" {
			rootOK = m.Version == "v0.0.0-20261012015322-ed54c505eafe" && m.Replace == nil
		}
	}
	if !rootOK || !sageOK {
		return nil, errors.New("unpinned or replaced subject module")
	}
	return &Subject{info: core.SubjectInfo{Name: "did-go/advanced/sage-projection", Version: Version, Revision: "2ef282b40ccfe243c6cf3b1c05594e02171126cc"}}, nil
}
func (s *Subject) Describe() core.SubjectInfo          { return s.info }
func (*Subject) Supports(string, core.Capability) bool { return false }

// fixtureSource is explicitly not an authoritative registry implementation.
type fixtureSource struct{ record didsage.Record }

func (s fixtureSource) Observe(context.Context, did.DID) (didsage.Record, error) {
	return s.record, nil
}
func (*Subject) Project(ctx context.Context, in sageprojection.Record, version string) (sageprojection.Result, error) {
	out := sageprojection.Result{}
	mt := "application/did+json"
	if version == "1.1" {
		mt = "application/did"
	} else if version != "1.0" {
		return out, errors.New("unsupported projection version")
	}
	d, e := did.Parse(in.DID)
	if e != nil {
		return out, e
	}
	issued := int64(1799999000)
	r := didsage.Record{DID: d, Controller: "fixture-controller", State: didsage.State(in.State), Version: in.Version,
		Services:    []didsage.Service{{Name: "a2a", Type: "A2AInterface", URI: "https://agent.example/a2a"}},
		Observation: didsage.Observation{Issued: &issued, Time: 1800000000, Source: "inspector-fixture-only"}}
	for _, k := range in.Keys {
		raw, err := hex.DecodeString(k.MaterialHex)
		if err != nil {
			return out, err
		}
		r.Keys = append(r.Keys, didsage.Key{Name: k.Name, Alg: k.Algorithm, Material: raw, State: didsage.KeyState(k.State), Expires: k.Expires})
	}
	res := didsage.Respond(ctx, fixtureSource{r}, didsage.Request{DID: d, Accept: mt}, producer.New())
	out.Raw = res.Body
	out.MediaType = res.ContentType
	if res.Problem != nil {
		out.ProblemCode = string(res.Problem.Code)
	}
	return out, nil
}
