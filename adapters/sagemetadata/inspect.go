// Package sagemetadata observes transparent metadata preservation against a
// separately pinned root module. Historical subjects remain unchanged.
package sagemetadata

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
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
)

const ModulePath = "github.com/sage-x-project/did-go"
const Version = "v0.0.0-20261017133212-e0b46f48cc14"
const Revision = "e0b46f48cc14581134ed3055baadf3b22cf4ce18"
const Sum = "h1:D3drLWqB0gQyb1/qo54oi5BQUKjH1CkV6Lys0m8RfW0="

// Subject observes a controlled downstream client, not an authoritative registry.
type Subject struct{}

func identify(read func() (*debug.BuildInfo, bool)) (*Subject, error) {
	bi, ok := read()
	if !ok || bi == nil {
		return nil, errors.New("missing metadata build identity")
	}
	count := 0
	for _, module := range bi.Deps {
		if module.Path == ModulePath {
			if module.Version != Version || module.Sum != Sum || module.Replace != nil {
				return nil, errors.New("unpinned or replaced metadata subject")
			}
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("missing or duplicate metadata module")
	}
	return &Subject{}, nil
}

func (*Subject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "did-go/metadata-presence", Version: Version, Revision: Revision}
}
func (*Subject) Supports(string, core.Capability) bool { return false }

// InspectClient delegates one controlled upstream reply to the actual client.
func (*Subject) InspectClient(ctx context.Context, record sageprojection.Record, q sageresolution.ClientRequest) (sageresolution.ClientResult, error) {
	if q.Request.Function != "resolve" || len(q.Reply) == 0 {
		return sageresolution.ClientResult{}, errors.New("requires a controlled upstream resolution reply")
	}
	return (&sage.Subject{}).InspectClient(ctx, record, q)
}

// Evidence keeps the new report separate from historical subject results.
type Evidence struct {
	Scope                string         `json:"scope"`
	RuntimeResultsMerged bool           `json:"runtime_results_merged"`
	Report               report.Report  `json:"report"`
	Raw                  core.RunResult `json:"raw"`
}

// Write runs the unchanged upstream metadata case with its original input.
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
		if c.ID == "did-1.1/sage-resolution/remaining-proxy-metadata" {
			selected = append(selected, c)
		}
	}
	if len(selected) != 1 {
		return errors.New("the frozen metadata case is required")
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
		Scope:                "Selected upstream metadata preservation only; proof signatures, SAGE projector adoption and operational authority are not established.",
		RuntimeResultsMerged: false, Report: report.Build(in), Raw: raw,
	})
}
