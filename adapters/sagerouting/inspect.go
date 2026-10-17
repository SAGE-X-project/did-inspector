// Package sagerouting observes explicitly configured intermediate document
// retrieval against a separately identified root module.
package sagerouting

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-inspector/adapters/sage"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
)

const ModulePath = "github.com/sage-x-project/did-go"
const Version = "v0.0.0-20261017081155-ee7d5fb003cf"
const Revision = "ee7d5fb003cf2d2ca4417f587547e40539cd9f2c"
const Sum = "h1:MjxUITQFUEiI7noGN/Vyxsh4yLDemMeggZ/COQeHOWs="

// Subject observes literal routing calls, not SAGE registry resolution.
type Subject struct{}

func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing routing build identity")
	}
	count := 0
	for _, module := range bi.Deps {
		if module.Path == ModulePath {
			if module.Version != Version || module.Sum != Sum || module.Replace != nil {
				return nil, errors.New("unpinned or replaced routing subject")
			}
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("missing or duplicate routing module")
	}
	return &Subject{}, nil
}

func (*Subject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "did-go/dereferencing-options", Version: Version, Revision: Revision}
}
func (*Subject) Supports(string, core.Capability) bool { return false }

// InspectRouting observes only native dereferencing with an explicitly
// configured intermediate resolver. It does not infer a verdict.
func (*Subject) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	if q.Request.Function != "dereference" {
		return sageresolution.RoutingResult{}, errors.New("only literal dereferencing observations are supported")
	}
	return sage.ObserveRouting(ctx, q, resolver.ForDereferencing())
}

//go:embed control-document.json
var controlDocument []byte

func strictControl() (sageresolution.RoutingResult, error) {
	return sage.ObserveRouting(context.Background(), sageresolution.RoutingRequest{
		Document: sageresolution.ConsumptionRequest{Data: controlDocument, MediaType: "application/did"},
		Request:  sageresolution.Request{Function: "resolve", Input: "did:example:123", Accept: "text/uri-list"},
	})
}

// Evidence keeps the new report separate from historical subject results.
type Evidence struct {
	Scope                string                         `json:"scope"`
	RuntimeResultsMerged bool                           `json:"runtime_results_merged"`
	Report               report.Report                  `json:"report"`
	Raw                  core.RunResult                 `json:"raw"`
	Controls             []sageresolution.RoutingResult `json:"controls"`
}

// Write runs twelve unchanged routing cases and preserves complete raw inputs
// and actual observations. Unobserved statements remain NOT_RUN.
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
		if strings.HasPrefix(c.ID, "did-1.1/sage-resolution/remaining-routing-") {
			selected = append(selected, c)
		}
	}
	if len(selected) != 12 {
		return errors.New("the twelve frozen routing cases are required")
	}
	p.Cases = selected
	before, err := strictControl()
	if err != nil {
		return err
	}
	runner := core.Runner{Now: func() time.Time { return time.Time{} }, CaseTimeout: 5 * time.Second}
	raw, err := runner.Run(context.Background(), p, subject)
	if err != nil {
		return err
	}
	after, err := strictControl()
	if err != nil {
		return err
	}
	in, err := report.InputFor(p, raw, revision)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(Evidence{
		Scope:                "Selected literal dereferencing options and service results only; full SAGE conformance and operational authority are not established.",
		RuntimeResultsMerged: false, Report: report.Build(in), Raw: raw, Controls: []sageresolution.RoutingResult{before, after},
	})
}
