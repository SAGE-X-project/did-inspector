package core

import "slices"

// Verdict is the outcome of one observation or, aggregated, of one
// statement.
type Verdict string

// Verdicts.
const (
	// Pass: the subject did what the statement requires.
	Pass Verdict = "PASS"
	// Fail: the subject did not; the observation records expected and
	// observed values.
	Fail Verdict = "FAIL"
	// NotSupported: the subject declares the capability the case needs
	// unsupported.
	NotSupported Verdict = "NOT_SUPPORTED"
	// NotApplicable: the statement does not apply to this input or subject.
	NotApplicable Verdict = "NOT_APPLICABLE"
	// Error: the case itself could not run to a judgment.
	Error Verdict = "ERROR"
	// NotRun: no observation judged the statement. It is a statement
	// verdict only; no observation carries it.
	NotRun Verdict = "NOT_RUN"
)

// Verdicts returns every verdict in report order.
func Verdicts() []Verdict {
	return []Verdict{Pass, Fail, NotSupported, NotApplicable, Error, NotRun}
}

// rank orders observation verdicts for aggregation: a higher rank wins.
var rank = map[Verdict]int{
	NotApplicable: 1,
	Pass:          2,
	NotSupported:  3,
	Error:         4,
	Fail:          5,
}

// IsObservation reports whether v may be the verdict of an observation.
func (v Verdict) IsObservation() bool {
	_, ok := rank[v]
	return ok
}

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	return slices.Contains(Verdicts(), v)
}

// Aggregate returns a statement's verdict from the verdicts of its
// observations: the worst one, with FAIL > ERROR > NOT_SUPPORTED > PASS.
// NOT_APPLICABLE ranks below PASS, so a statement is NOT_APPLICABLE only when
// every observation is. A statement without observations is NOT_RUN. An
// unknown verdict counts as ERROR.
func Aggregate(vs []Verdict) Verdict {
	if len(vs) == 0 {
		return NotRun
	}
	worst, worstRank := NotRun, 0
	for _, v := range vs {
		r, ok := rank[v]
		if !ok {
			v, r = Error, rank[Error]
		}
		if r > worstRank {
			worst, worstRank = v, r
		}
	}
	return worst
}
