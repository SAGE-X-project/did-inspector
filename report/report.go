// Package report turns the result of one run into the inspector's report:
// a JSON document with deterministic ordering and a text summary.
//
// A report is evidence for that run only: the subject revision, profile,
// statements and inspector revision it names. It is not a certification.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/sage-x-project/did-inspector/core"
)

// Format identifies the report format and its version.
const Format = "did-inspector-report/1"

// Spec is one pinned publication of the profile.
type Spec struct {
	Key    string `json:"key"`
	URL    string `json:"url"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

// StatementRef is one statement of the profile with its scope decision.
type StatementRef struct {
	ID    string
	Scope string
}

// Input is everything a report is built from.
type Input struct {
	Result            core.RunResult
	InspectorRevision string
	Specs             []Spec
	// Statements are every statement of the profile's spec keys, in order.
	Statements []StatementRef
}

// Inspector identifies the inspector that produced the report.
type Inspector struct {
	Revision string `json:"revision"`
}

// Observation is one observation of a statement, with the case that made it.
type Observation struct {
	Case string `json:"case"`
	core.Observation
}

// Statement is the outcome for one statement.
type Statement struct {
	ID string `json:"id"`
	// Scope is the inspector's scope decision; empty for a statement that is
	// not among the profile's statements.
	Scope   string       `json:"scope,omitempty"`
	Verdict core.Verdict `json:"verdict"`
	// Cases are the ids of the cases that judged the statement.
	Cases []string `json:"cases,omitempty"`
	// Findings are the observations that were not PASS: failures with their
	// expected and observed values, errors, unsupported and inapplicable
	// cases.
	Findings []Observation `json:"findings,omitempty"`
	// Unknown is set when a case judged a statement the profile does not
	// have.
	Unknown bool `json:"unknown,omitempty"`
}

// Totals counts statements per verdict.
type Totals struct {
	Statements    int `json:"statements"`
	Pass          int `json:"PASS"`
	Fail          int `json:"FAIL"`
	NotSupported  int `json:"NOT_SUPPORTED"`
	NotApplicable int `json:"NOT_APPLICABLE"`
	Error         int `json:"ERROR"`
	NotRun        int `json:"NOT_RUN"`
}

func (t *Totals) add(v core.Verdict) {
	t.Statements++
	switch v {
	case core.Pass:
		t.Pass++
	case core.Fail:
		t.Fail++
	case core.NotSupported:
		t.NotSupported++
	case core.NotApplicable:
		t.NotApplicable++
	case core.Error:
		t.Error++
	default:
		t.NotRun++
	}
}

// Count returns the total for one verdict.
func (t Totals) Count(v core.Verdict) int {
	switch v {
	case core.Pass:
		return t.Pass
	case core.Fail:
		return t.Fail
	case core.NotSupported:
		return t.NotSupported
	case core.NotApplicable:
		return t.NotApplicable
	case core.Error:
		return t.Error
	case core.NotRun:
		return t.NotRun
	}
	return 0
}

// Case summarizes one case of the run.
type Case struct {
	ID           string       `json:"id"`
	Statements   []string     `json:"statements"`
	Verdict      core.Verdict `json:"verdict"`
	Observations int          `json:"observations"`
}

// Report is the inspector's report of one run.
type Report struct {
	Format     string           `json:"format"`
	Inspector  Inspector        `json:"inspector"`
	Subject    core.SubjectInfo `json:"subject"`
	Profile    string           `json:"profile"`
	Specs      []Spec           `json:"specs"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Totals     Totals           `json:"totals"`
	Statements []Statement      `json:"statements"`
	Cases      []Case           `json:"cases"`
	NotRun     []string         `json:"not_run"`
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Build makes the report. Statements follow the order of in.Statements;
// statements that cases judged but the profile does not have follow, sorted
// by id and marked unknown. Cases and findings follow the order of the run.
func Build(in Input) Report {
	r := Report{
		Format:     Format,
		Inspector:  Inspector{Revision: in.InspectorRevision},
		Subject:    in.Result.Subject,
		Profile:    in.Result.Profile,
		Specs:      append([]Spec{}, in.Specs...),
		StartedAt:  formatTime(in.Result.StartedAt),
		FinishedAt: formatTime(in.Result.FinishedAt),
		Statements: []Statement{},
		Cases:      []Case{},
		NotRun:     []string{},
	}
	obsBy := map[string][]Observation{}
	casesBy := map[string][]string{}
	for _, cr := range in.Result.Cases {
		var vs []core.Verdict
		for _, o := range cr.Observations {
			vs = append(vs, o.Verdict)
			obsBy[o.Statement] = append(obsBy[o.Statement], Observation{Case: cr.Case, Observation: o})
			if !slices.Contains(casesBy[o.Statement], cr.Case) {
				casesBy[o.Statement] = append(casesBy[o.Statement], cr.Case)
			}
		}
		r.Cases = append(r.Cases, Case{
			ID:           cr.Case,
			Statements:   append([]string{}, cr.Statements...),
			Verdict:      core.Aggregate(vs),
			Observations: len(cr.Observations),
		})
	}
	known := map[string]bool{}
	for _, ref := range in.Statements {
		known[ref.ID] = true
		r.addStatement(ref.ID, ref.Scope, false, obsBy[ref.ID], casesBy[ref.ID])
	}
	var unknown []string
	for id := range obsBy {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	slices.Sort(unknown)
	for _, id := range unknown {
		r.addStatement(id, "", true, obsBy[id], casesBy[id])
	}
	return r
}

func (r *Report) addStatement(id, scope string, unknown bool, obs []Observation, cases []string) {
	vs := make([]core.Verdict, len(obs))
	var findings []Observation
	for i, o := range obs {
		vs[i] = o.Verdict
		if o.Verdict != core.Pass {
			findings = append(findings, o)
		}
	}
	v := core.Aggregate(vs)
	r.Statements = append(r.Statements, Statement{
		ID: id, Scope: scope, Verdict: v, Cases: cases, Findings: findings, Unknown: unknown,
	})
	r.Totals.add(v)
	if v == core.NotRun {
		r.NotRun = append(r.NotRun, id)
	}
}

// MarshalIndent renders the report as indented JSON with a trailing
// newline. The output is deterministic for a given report.
func (r Report) MarshalIndent() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	data, err := r.MarshalIndent()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Decode reads a report written by WriteJSON.
func Decode(data []byte) (Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return Report{}, fmt.Errorf("report: %w", err)
	}
	if r.Format != Format {
		return Report{}, fmt.Errorf("report: format %q, want %q", r.Format, Format)
	}
	return r, nil
}
