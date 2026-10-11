package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

// Disclaimer closes every text summary.
const Disclaimer = "This report is evidence for this run only; it is not a certification."

// WriteText writes a human-readable summary: the run header, totals per
// verdict overall and per level, the conformance gate, and every statement
// whose verdict is FAIL, ERROR or NOT_SUPPORTED with its findings,
// requirements first and recommendations after them.
func (r Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "did-inspector report (%s)\n", r.Format)
	fmt.Fprintf(&b, "subject:   %s %s (revision %s)\n", r.Subject.Name, r.Subject.Version, orNone(r.Subject.Revision))
	fmt.Fprintf(&b, "profile:   %s\n", r.Profile)
	fmt.Fprintf(&b, "inspector: revision %s\n", orNone(r.Inspector.Revision))
	for _, s := range r.Specs {
		fmt.Fprintf(&b, "spec:      %s sha256:%s\n", s.Key, s.SHA256)
	}
	fmt.Fprintf(&b, "run:       %s to %s\n", orNone(r.StartedAt), orNone(r.FinishedAt))
	fmt.Fprintf(&b, "cases:     %d\n", len(r.Cases))
	fmt.Fprintf(&b, "statements: %d\n", r.Totals.Statements)
	writeTotals(&b, r.Totals)
	for _, level := range statements.Levels() {
		t := r.TotalsByLevel.For(level)
		fmt.Fprintf(&b, "%s statements: %d\n", level, t.Statements)
		writeTotals(&b, t)
	}
	if n := len(r.GateFailures()); n > 0 {
		fmt.Fprintf(&b, "gate:      FAIL (%d requirement-level statement(s) FAIL or ERROR)\n", n)
	} else {
		b.WriteString("gate:      PASS (no requirement-level statement is FAIL or ERROR)\n")
	}
	writeProblems(&b, "findings:", r.Statements, false)
	writeProblems(&b, "recommendation findings (not counted by the gate):", r.Statements, true)
	b.WriteString(Disclaimer + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func writeTotals(b *strings.Builder, t Totals) {
	for _, v := range core.Verdicts() {
		fmt.Fprintf(b, "  %-15s %d\n", v, t.Count(v))
	}
}

// writeProblems writes the FAIL, ERROR and NOT_SUPPORTED statements of one
// side of the level split under a heading.
func writeProblems(b *strings.Builder, heading string, sts []Statement, recommendations bool) {
	var problems []Statement
	for _, s := range sts {
		if s.IsRecommendation() != recommendations {
			continue
		}
		switch s.Verdict {
		case core.Fail, core.Error, core.NotSupported:
			problems = append(problems, s)
		}
	}
	if len(problems) == 0 {
		return
	}
	b.WriteString(heading + "\n")
	for _, s := range problems {
		fmt.Fprintf(b, "  %s %s\n", s.Verdict, s.ID)
		for _, f := range s.Findings {
			writeFinding(b, f)
		}
	}
}

func writeFinding(b *strings.Builder, f Observation) {
	fmt.Fprintf(b, "    [%s] %s", f.Case, f.Verdict)
	if f.Input != "" {
		fmt.Fprintf(b, " input=%q", f.Input)
	}
	if f.Expected != "" || f.Observed != "" {
		fmt.Fprintf(b, " expected=%q observed=%q", f.Expected, f.Observed)
	}
	if f.Detail != "" {
		fmt.Fprintf(b, " detail=%q", f.Detail)
	}
	b.WriteString("\n")
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
