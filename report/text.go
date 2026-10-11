package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// Disclaimer closes every text summary.
const Disclaimer = "This report is evidence for this run only; it is not a certification."

// WriteText writes a human-readable summary: the run header, totals per
// verdict, and every statement whose verdict is FAIL, ERROR or
// NOT_SUPPORTED with its findings.
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
	for _, v := range core.Verdicts() {
		fmt.Fprintf(&b, "  %-15s %d\n", v, r.Totals.Count(v))
	}
	var problems []Statement
	for _, s := range r.Statements {
		switch s.Verdict {
		case core.Fail, core.Error, core.NotSupported:
			problems = append(problems, s)
		}
	}
	if len(problems) > 0 {
		b.WriteString("findings:\n")
		for _, s := range problems {
			fmt.Fprintf(&b, "  %s %s\n", s.Verdict, s.ID)
			for _, f := range s.Findings {
				writeFinding(&b, f)
			}
		}
	}
	b.WriteString(Disclaimer + "\n")
	_, err := io.WriteString(w, b.String())
	return err
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
