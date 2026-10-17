// Package sagefragments observes transparent fragment preservation against a
// separately pinned root module. Historical subjects remain unchanged.
package sagefragments

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
const Version = "v0.0.0-20261017145616-073dc7a77dd8"
const Revision = "073dc7a77dd8d786822cddf7401abd8698d3453d"
const Sum = "h1:FNmRm7/U6/Wa976t9yODH9FAqQ+V2xGFsrk1F8WHt1w="

// Subject observes literal native calls, not an authoritative registry.
type Subject struct{}

func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing fragment build identity")
	}
	count := 0
	for _, module := range bi.Deps {
		if module.Path == ModulePath {
			if module.Version != Version || module.Sum != Sum || module.Replace != nil {
				return nil, errors.New("unpinned or replaced fragment subject")
			}
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("missing or duplicate fragment module")
	}
	return &Subject{}, nil
}

func (*Subject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "did-go/recursive-fragments", Version: Version, Revision: Revision}
}
func (*Subject) Supports(string, core.Capability) bool { return false }

// InspectRouting delegates unchanged literal native requests to the actual root.
func (*Subject) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	if q.Request.Function != "dereference" {
		return sageresolution.RoutingResult{}, errors.New("requires native literal dereferencing")
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

// Write runs five unchanged recursive-search cases with their original inputs.
// Unobserved statements remain NOT_RUN.
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
		if strings.HasPrefix(c.ID, "did-1.1/sage-resolution/fragment-search-") {
			selected = append(selected, c)
		}
	}
	if len(selected) != 5 {
		return errors.New("the five frozen fragment cases are required")
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
		Scope:                "Selected public recursive fragment maps only; SAGE consumer adoption, numeric client conversion and operational authority are not established.",
		RuntimeResultsMerged: false, Report: report.Build(in), Raw: raw,
	})
}
