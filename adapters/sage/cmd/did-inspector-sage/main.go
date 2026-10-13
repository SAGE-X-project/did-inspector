// Command did-inspector-sage runs an inspection profile of did-inspector
// against SAGE projection or resolution interfaces through the separate adapter.
//
// Usage:
//
//	did-inspector-sage --profile <did-core-1.0|did-1.1> [--scope projection|resolution] [--out report.json] [--raw-out cases.json] [--deterministic] [--inspector-revision <rev>]
//
// It runs the profile with the inspector's runner, writes the JSON report to
// --out and prints the text summary. --deterministic leaves the run times
// out of the report, so that two runs of the same revisions give the same
// bytes. --inspector-revision overrides the revision read from the build
// information. The exit status is 0 when the run completed, whatever the
// verdicts, 1 when it could not run and 2 for a usage error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/sage-x-project/did-inspector/adapters/sage"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
)

const usage = "usage: did-inspector-sage --profile <did-core-1.0|did-1.1> [--scope projection|resolution] [--out report.json] [--raw-out cases.json] [--deterministic] [--inspector-revision <rev>]\n"

// env is what the command needs from the outside world.
type env struct {
	stdout, stderr io.Writer
	subject        func() (core.Subject, error)
	now            func() time.Time
	revision       string
}

func main() {
	os.Exit(run(os.Args[1:], env{
		stdout:   os.Stdout,
		stderr:   os.Stderr,
		subject:  func() (core.Subject, error) { return sage.New() },
		now:      time.Now,
		revision: buildRevision(debug.ReadBuildInfo),
	}))
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func run(args []string, e env) int {
	err := runProfile(args, e)
	var ue usageError
	switch {
	case errors.As(err, &ue):
		_, _ = fmt.Fprintf(e.stderr, "did-inspector-sage: %v\n%s", err, usage)
		return 2
	case err != nil:
		_, _ = fmt.Fprintf(e.stderr, "did-inspector-sage: %v\n", err)
		return 1
	}
	return 0
}

func runProfile(args []string, e env) error {
	fs := flag.NewFlagSet("did-inspector-sage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profileName := fs.String("profile", "", "profile to run")
	scope := fs.String("scope", "projection", "projection or resolution observations")
	out := fs.String("out", "", "file to write the JSON report to")
	rawOut := fs.String("raw-out", "", "preserve all case inputs and observed bytes")
	deterministic := fs.Bool("deterministic", false, "leave the run times out of the report")
	revision := fs.String("inspector-revision", "", "inspector revision to report")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Sprintf("unexpected argument %q", fs.Arg(0))}
	}
	if *profileName == "" {
		return usageError{"--profile is required"}
	}
	if *out != "" && *rawOut != "" {
		a, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		b, err := filepath.Abs(*rawOut)
		if err != nil {
			return err
		}
		same := a == b
		first, e1 := os.Stat(a)
		second, e2 := os.Stat(b)
		if e1 == nil && e2 == nil && os.SameFile(first, second) {
			same = true
		}
		if same {
			return usageError{"--out and --raw-out must name different files"}
		}
	}
	p, err := sageprojection.Profile(*profileName)
	if *scope == "resolution" {
		p, err = sageresolution.Profile(*profileName)
	} else if *scope != "projection" {
		return usageError{"unknown inspection scope"}
	}
	if err != nil {
		return usageError{err.Error()}
	}

	runner := core.Runner{Now: e.now, CaseTimeout: 5 * time.Second}
	if *deterministic {
		runner.Now = func() time.Time { return time.Time{} }
	}
	subject, err := e.subject()
	if err != nil {
		return err
	}
	if *scope == "resolution" {
		if s, ok := subject.(*sage.Subject); ok {
			subject = s.ResolutionIdentity()
		}
	}
	if c, ok := subject.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	res, err := runner.Run(context.Background(), p, subject)
	if err != nil {
		return err
	}
	rev := e.revision
	if *revision != "" {
		rev = *revision
	}
	in, err := report.InputFor(p, res, rev)
	if err != nil {
		return err
	}
	rep := report.Build(in)
	if *out != "" {
		data, err := rep.MarshalIndent()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
	}
	if *rawOut != "" {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(*rawOut, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	scopeText := "produced SAGE fixture documents only"
	if *scope == "resolution" {
		scopeText = "SAGE native interfaces and inspector-owned loopback TLS only"
	}
	if _, err := fmt.Fprintln(e.stdout, "Scope: "+scopeText+"; unobserved statements remain NOT_RUN; full standard conformance is NOT_ESTABLISHED."); err != nil {
		return err
	}
	return rep.WriteText(e.stdout)
}

// buildRevision returns the VCS revision the binary was built from, with
// "+dirty" for a modified tree, or "devel" when it is unknown.
func buildRevision(read func() (*debug.BuildInfo, bool)) string {
	info, ok := read()
	if !ok {
		return "devel"
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return "devel"
	}
	if modified == "true" {
		rev += "+dirty"
	}
	return rev
}
