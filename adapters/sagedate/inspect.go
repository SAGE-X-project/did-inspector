// Package sagedate inspects selected consumer syntax against an independently
// identified repaired root module. It preserves the older SAGE subject pins.
package sagedate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sage-x-project/did-inspector/adapters/sage"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
)

const ModulePath = "github.com/sage-x-project/did-go"
const Version = "v0.0.0-20261017064709-bff3bf77a78d"
const Revision = "bff3bf77a78defacbc8bb45533a0456e9135c433"
const Sum = "h1:Ks8DbF2NLyDNH0K8BgzfjLpferYL236UvLFVZkAvAoY="

// Subject observes only literal consumer calls, not SAGE registry resolution.
type Subject struct{}

func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing consumer build identity")
	}
	count := 0
	for _, module := range bi.Deps {
		if module.Path == ModulePath {
			if module.Version != Version || module.Sum != Sum || module.Replace != nil {
				return nil, errors.New("unpinned or replaced consumer subject")
			}
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("missing or duplicate consumer module")
	}
	return &Subject{}, nil
}

func (*Subject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "did-go/key-timestamp-consumer", Version: Version, Revision: Revision}
}
func (*Subject) Supports(string, core.Capability) bool { return false }

// InspectPolicy preserves the existing independent date-case observation
// contract while excluding relying-party and registry capabilities.
func (*Subject) InspectPolicy(ctx context.Context, q sageresolution.PolicyRequest) (sageresolution.PolicyResult, error) {
	if q.Mode != "consume" {
		return sageresolution.PolicyResult{}, errors.New("only literal consumer observations are supported")
	}
	return sage.ObservePolicy(ctx, q)
}

// Evidence keeps the new report separate from historical subject results.
type Evidence struct {
	Scope                string         `json:"scope"`
	RuntimeResultsMerged bool           `json:"runtime_results_merged"`
	Report               report.Report  `json:"report"`
	Raw                  core.RunResult `json:"raw"`
}

// Write runs the two unchanged date cases and preserves their complete raw
// inputs and observations. All unobserved statements remain NOT_RUN.
func Write(out io.Writer, revision string) error {
	return inspect(out, revision, debug.ReadBuildInfo)
}

func inspect(out io.Writer, revision string, read func() (*debug.BuildInfo, bool)) error {
	subject, err := identify(read)
	if err != nil {
		return err
	}
	return write(out, revision, subject, sageresolution.Profile)
}

func write(out io.Writer, revision string, subject core.Subject, load func(string) (core.Profile, error)) error {
	if strings.TrimSpace(revision) == "" {
		return errors.New("an inspector revision is required")
	}
	p, err := load("did-1.1")
	if err != nil {
		return err
	}
	selected := []core.Case{}
	for _, c := range p.Cases {
		if c.ID == "did-1.1/sage-resolution/key-policy-format-expires" || c.ID == "did-1.1/sage-resolution/key-policy-format-revoked" {
			selected = append(selected, c)
		}
	}
	if len(selected) != 2 {
		return errors.New("the two frozen date cases are required")
	}
	p.Cases = selected
	runner := core.Runner{Now: func() time.Time { return time.Time{} }, CaseTimeout: 5 * time.Second}
	raw, err := runner.Run(context.Background(), p, subject)
	if err != nil {
		return err
	}
	in, err := report.InputFor(p, raw, revision)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(Evidence{
		Scope:                "Selected literal consumer timestamp syntax only; complete XML Schema and SAGE conformance are not established.",
		RuntimeResultsMerged: false, Report: report.Build(in), Raw: raw,
	})
}
