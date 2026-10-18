// Package sageexpansion observes reviewed relative identifier expansion against a
// separately pinned root module. Historical subjects remain unchanged.
package sageexpansion

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
const Version = "v0.0.0-20261018060817-8d2c9e801fc1"
const Revision = "8d2c9e801fc10ead3e04bf8d5c0a6c3e5e7990ba"
const Sum = "h1:8WZlyuKGZ+MzOhzAG/0u13YlE61Ka0J6WVPv7K11iuA="

// Subject observes literal native calls, not an authoritative registry.
type Subject struct{}

func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing expansion build identity")
	}
	count := 0
	for _, module := range bi.Deps {
		if module.Path == ModulePath {
			if module.Version != Version || module.Sum != Sum || module.Replace != nil {
				return nil, errors.New("unpinned or replaced expansion subject")
			}
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("missing or duplicate expansion module")
	}
	return &Subject{}, nil
}

func (*Subject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "did-go/relative-expansion", Version: Version, Revision: Revision}
}
func (*Subject) Supports(string, core.Capability) bool { return false }

// InspectRouting delegates unchanged literal native requests to the actual root.
func (*Subject) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	if q.Request.Function != "resolve" {
		return sageresolution.RoutingResult{}, errors.New("requires native literal resolution")
	}
	return sage.ObserveRouting(ctx, q)
}

// Evidence keeps the new report separate from historical subject results.
type Evidence struct {
	Scope                string         `json:"scope"`
	RuntimeResultsMerged bool           `json:"runtime_results_merged"`
	Report               report.Report  `json:"report"`
	Raw                  core.RunResult `json:"raw"`
}

// Write runs unchanged relative-expansion fixtures with their original inputs.
// Unobserved statements remain NOT_RUN.
func Write(out io.Writer, revision string) error {
	return inspect(out, revision, debug.ReadBuildInfo)
}

func inspect(out io.Writer, revision string, read func() (*debug.BuildInfo, bool)) error {
	subject, err := identify(read)
	if err != nil {
		return err
	}
	return write(out, revision, subject, sageresolution.RelativeExpansionProfile)
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
		if c.ID == "did-1.1/sage-resolution/repaired-relative-expansion" {
			selected = append(selected, c)
		}
	}
	if len(selected) != 1 {
		return errors.New("the separate repaired expansion case is required")
	}
	p.Cases = selected
	runner := core.Runner{Now: func() time.Time { return time.Time{} }, CaseTimeout: 2 * time.Minute}
	raw, err := runner.Run(context.Background(), p, subject)
	if err != nil {
		return err
	}
	in, err := report.InputFor(p, raw, revision)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(Evidence{
		Scope:                "Selected reviewed public relative identifier expansion only; full URI semantics, SAGE consumer adoption and operational authority are not established.",
		RuntimeResultsMerged: false, Report: report.Build(in), Raw: raw,
	})
}
