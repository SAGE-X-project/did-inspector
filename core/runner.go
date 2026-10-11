package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CaseResult is what one case observed in a run.
type CaseResult struct {
	Case         string        `json:"case"`
	Statements   []string      `json:"statements"`
	Observations []Observation `json:"observations"`
}

// RunResult is the outcome of running one profile against one subject.
type RunResult struct {
	Profile    string       `json:"profile"`
	Subject    SubjectInfo  `json:"subject"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Cases      []CaseResult `json:"cases"`
}

// StatementVerdicts aggregates the observations of a run per statement. A
// statement that no observation judged is absent; its verdict is NOT_RUN.
func (r RunResult) StatementVerdicts() map[string]Verdict {
	byStatement := map[string][]Verdict{}
	for _, c := range r.Cases {
		for _, o := range c.Observations {
			byStatement[o.Statement] = append(byStatement[o.Statement], o.Verdict)
		}
	}
	out := make(map[string]Verdict, len(byStatement))
	for id, vs := range byStatement {
		out[id] = Aggregate(vs)
	}
	return out
}

// Runner runs the cases of a profile against a subject.
type Runner struct {
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
	// CaseTimeout bounds each case; zero means no bound beyond the run's
	// context.
	CaseTimeout time.Duration
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Run validates the profile and runs every case in order. A case whose
// capability the subject does not support yields NOT_SUPPORTED for each of
// its statements; a case that panics, reports no observation, or reports an
// ill-formed observation yields ERROR. Run returns an error only when the
// profile or subject is unusable.
func (r Runner) Run(ctx context.Context, p Profile, s Subject) (RunResult, error) {
	if s == nil {
		return RunResult{}, errors.New("runner: nil subject")
	}
	if err := p.Validate(); err != nil {
		return RunResult{}, fmt.Errorf("runner: %w", err)
	}
	res := RunResult{Profile: p.Name, StartedAt: r.now()}
	info, err := describe(s)
	if err != nil {
		return RunResult{}, fmt.Errorf("runner: %w", err)
	}
	res.Subject = info
	for _, c := range p.Cases {
		res.Cases = append(res.Cases, CaseResult{
			Case:         c.ID,
			Statements:   append([]string(nil), c.Statements...),
			Observations: r.runCase(ctx, p.Name, c, s),
		})
	}
	res.FinishedAt = r.now()
	return res, nil
}

func describe(s Subject) (info SubjectInfo, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("subject Describe panicked: %v", p)
		}
	}()
	return s.Describe(), nil
}

// each returns one observation per statement of c with the verdict and
// detail given.
func each(c Case, v Verdict, detail string) []Observation {
	out := make([]Observation, len(c.Statements))
	for i, st := range c.Statements {
		out[i] = Observation{Statement: st, Verdict: v, Detail: detail}
	}
	return out
}

func (r Runner) runCase(ctx context.Context, profile string, c Case, s Subject) (obs []Observation) {
	defer func() {
		if p := recover(); p != nil {
			obs = each(c, Error, fmt.Sprintf("case panicked: %v", p))
		}
	}()
	if err := ctx.Err(); err != nil {
		return each(c, Error, "run cancelled before the case: "+err.Error())
	}
	for _, need := range c.Needs {
		if !s.Supports(profile, need) {
			return each(c, NotSupported, (&CapabilityError{Profile: profile, Capability: need, Unsupported: true}).Error())
		}
		if !Implements(s, need) {
			return each(c, Error, (&CapabilityError{Profile: profile, Capability: need}).Error())
		}
	}
	caseCtx := ctx
	if r.CaseTimeout > 0 {
		var cancel context.CancelFunc
		caseCtx, cancel = context.WithTimeout(ctx, r.CaseTimeout)
		defer cancel()
	}
	return checkObservations(c, c.Run(caseCtx, s))
}

// checkObservations replaces ill-formed observations with ERROR ones and
// drops observations of statements the case does not name.
func checkObservations(c Case, obs []Observation) []Observation {
	if len(obs) == 0 {
		return each(c, Error, "case reported no observation")
	}
	out := make([]Observation, 0, len(obs))
	var unnamed []string
	for _, o := range obs {
		switch {
		case !c.names(o.Statement):
			unnamed = append(unnamed, o.Statement)
		case !o.Verdict.IsObservation():
			out = append(out, Observation{
				Statement: o.Statement,
				Verdict:   Error,
				Input:     o.Input,
				Detail:    fmt.Sprintf("case reported verdict %q, which an observation cannot carry", o.Verdict),
			})
		case o.Verdict == Fail && o.Expected == "" && o.Observed == "":
			out = append(out, Observation{
				Statement: o.Statement,
				Verdict:   Error,
				Input:     o.Input,
				Detail:    "case reported FAIL without expected and observed values",
			})
		default:
			out = append(out, o)
		}
	}
	// A case that judges a statement it does not name is broken: its
	// statements get an ERROR, which outranks PASS, while its well-formed
	// observations, including any FAIL, are kept.
	if len(unnamed) > 0 {
		out = append(out, each(c, Error, fmt.Sprintf("case reported observations for statements it does not name: %q", unnamed))...)
	}
	return out
}
