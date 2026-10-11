// Command did-inspector inspects an implementation of W3C Decentralized
// Identifiers against the pinned specification text.
//
// Usage:
//
//	did-inspector list
//	did-inspector run --profile <profile> --subject <subject> [--out report.json]
//	did-inspector statements
//
// list prints the profiles and their cases; run runs one profile against one
// subject, writes the JSON report to --out and prints a text summary;
// statements prints the number of extracted statements per spec key, level
// and scope. The only built-in subject is "fixture", a configurable test
// subject; real implementations are reached through adapters.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
	"github.com/sage-x-project/did-inspector/profiles"
	"github.com/sage-x-project/did-inspector/report"
	"github.com/sage-x-project/did-inspector/statements"
)

const usage = `usage:
  did-inspector list
  did-inspector run --profile <profile> --subject <subject> [--out report.json]
  did-inspector statements
`

// env is what a command needs from the outside world.
type env struct {
	stdout, stderr io.Writer
	registry       func() (*profiles.Registry, error)
	subjects       map[string]func() core.Subject
	now            func() time.Time
	revision       string
}

func main() {
	os.Exit(run(os.Args[1:], defaultEnv()))
}

func defaultEnv() env {
	return env{
		stdout:   os.Stdout,
		stderr:   os.Stderr,
		registry: profiles.Default,
		subjects: map[string]func() core.Subject{
			"fixture": func() core.Subject { return coretest.New() },
		},
		now:      time.Now,
		revision: buildRevision(debug.ReadBuildInfo),
	}
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

func run(args []string, e env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(e.stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "list":
		err = cmdList(e)
	case "run":
		err = cmdRun(args[1:], e)
	case "statements":
		err = cmdStatements(e)
	case "help", "-h", "--help":
		if _, err := fmt.Fprint(e.stdout, usage); err != nil {
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintf(e.stderr, "did-inspector: unknown command %q\n%s", args[0], usage)
		return 2
	}
	var ue usageError
	switch {
	case errors.As(err, &ue):
		_, _ = fmt.Fprintf(e.stderr, "did-inspector: %v\n%s", err, usage)
		return 2
	case err != nil:
		_, _ = fmt.Fprintf(e.stderr, "did-inspector: %v\n", err)
		return 1
	}
	return 0
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func cmdList(e env) error {
	reg, err := e.registry()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, p := range reg.Profiles() {
		fmt.Fprintf(&b, "%s\t%s\n", p.Name, p.Title)
		fmt.Fprintf(&b, "  spec keys: %s\n", strings.Join(p.SpecKeys, ", "))
		fmt.Fprintf(&b, "  cases: %d\n", len(p.Cases))
		for _, c := range p.Cases {
			needs := make([]string, len(c.Needs))
			for i, n := range c.Needs {
				needs[i] = string(n)
			}
			fmt.Fprintf(&b, "    %s statements=%s needs=%s\n", c.ID, strings.Join(c.Statements, ","), strings.Join(needs, ","))
		}
	}
	names := make([]string, 0, len(e.subjects))
	for name := range e.subjects {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "subjects: %s\n", strings.Join(names, ", "))
	_, err = io.WriteString(e.stdout, b.String())
	return err
}

func cmdRun(args []string, e env) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profileName := fs.String("profile", "", "profile to run")
	subjectName := fs.String("subject", "", "subject to inspect")
	out := fs.String("out", "", "file to write the JSON report to")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Sprintf("unexpected argument %q", fs.Arg(0))}
	}
	if *profileName == "" || *subjectName == "" {
		return usageError{"run needs --profile and --subject"}
	}
	reg, err := e.registry()
	if err != nil {
		return err
	}
	p, ok := reg.Lookup(*profileName)
	if !ok {
		return fmt.Errorf("unknown profile %q", *profileName)
	}
	newSubject, ok := e.subjects[*subjectName]
	if !ok {
		return fmt.Errorf("unknown subject %q", *subjectName)
	}
	res, err := core.Runner{Now: e.now}.Run(context.Background(), p, newSubject())
	if err != nil {
		return err
	}
	in, err := report.InputFor(p, res, e.revision)
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
	return rep.WriteText(e.stdout)
}

func cmdStatements(e env) error {
	all, err := statements.CountByScope()
	if err != nil {
		return err
	}
	byLevel, err := statements.CountByLevel()
	if err != nil {
		return err
	}
	levels := statements.Levels()
	var b strings.Builder
	b.WriteString("spec key\tlevel\ttotal\tchecked\tnot-checkable\tpending\t\n")
	write := func(key, level string, c statements.Counts) {
		fmt.Fprintf(&b, "%s\t%s\t%d\t%d\t%d\t%d\t\n", key, level, c.Total, c.Checked, c.NotCheckable, c.Pending)
	}
	sums := make([]statements.Counts, len(levels)+1)
	for i, c := range all {
		rows := append([]statements.Counts{c}, byLevel[i*len(levels):(i+1)*len(levels)]...)
		for j, row := range rows {
			level := row.Level
			if j == 0 {
				level = "all"
			}
			write(c.Key, level, row)
			sums[j].Total += row.Total
			sums[j].Checked += row.Checked
			sums[j].NotCheckable += row.NotCheckable
			sums[j].Pending += row.Pending
		}
	}
	for j, sum := range sums {
		level := "all"
		if j > 0 {
			level = levels[j-1]
		}
		write("all", level, sum)
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	if _, err := io.WriteString(tw, b.String()); err != nil {
		return err
	}
	return tw.Flush()
}
