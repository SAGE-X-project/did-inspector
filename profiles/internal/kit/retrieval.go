package kit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// RetrievalFile is the format of testdata/retrieval.json: calls of the
// Retrieve Verification Method algorithm (CID 1.0 §3.3) with verification
// method identifiers of the fixture method, and the results the
// specification requires.
type RetrievalFile struct {
	Scenarios []Retrieval `json:"scenarios"`
}

// Retrieval becomes one case.
type Retrieval struct {
	// Case is the case id suffix.
	Case string `json:"case"`
	Note string `json:"note"`
	// VMIdentifier, Relationship and Options are the algorithm's inputs.
	VMIdentifier string         `json:"vmIdentifier"`
	Relationship string         `json:"relationship"`
	Options      map[string]any `json:"options"`
	// Expect are the checks, each with the statements it judges.
	Expect []RetrievalExpectation `json:"expect"`
}

// RetrievalExpectation is one check of a retrieval result.
type RetrievalExpectation struct {
	// Check names a function of RetrievalChecks.
	Check string `json:"check"`
	// Value is the check's argument.
	Value json.RawMessage `json:"value,omitempty"`
	// Statements are the statements the check judges.
	Statements []string `json:"statements"`
	// Partial says what the check does not judge of its statements.
	Partial string `json:"partial,omitempty"`
}

// Statements returns the statements of all expectations without repeats.
func (rv Retrieval) Statements() []string {
	lists := make([][]string, len(rv.Expect))
	for i, e := range rv.Expect {
		lists[i] = e.Statements
	}
	return Union(lists...)
}

// Retrieved is the outcome of one retrieval.
type Retrieved struct {
	Retrieval Retrieval
	Result    core.RetrievalResult
}

// RetrievalCheck judges a retrieval against an expectation's value. It
// returns whether the result conforms, the expected and observed values,
// and a note on what of the statement it does not judge.
type RetrievalCheck func(r Retrieved, value json.RawMessage) (ok bool, expected, observed, note string)

// RetrievalChecks are the checks retrieval scenarios can name.
var RetrievalChecks = map[string]RetrievalCheck{
	"returnsMethod":     checkReturnsMethod,
	"returnsIdentified": checkReturnsIdentified,
	"raisesError":       checkRaisesError,
}

// RetrievalCases returns one case per retrieval scenario. Every scenario
// dereferences DID URLs of the fixture method, so its case loads the
// registry first.
func RetrievalCases(profile string, reg *fixtures.Registry, f RetrievalFile) []core.Case {
	out := make([]core.Case, 0, len(f.Scenarios))
	for _, rv := range f.Scenarios {
		sts := rv.Statements()
		out = append(out, core.Case{
			ID:         profile + "/retrieve-verification-method/" + rv.Case,
			Profile:    profile,
			Statements: sts,
			Needs:      []core.Capability{core.CapFixtureMethod, core.CapVerificationMethodRetriever},
			Run: RegistryCase(reg, sts, func(ctx context.Context, s core.Subject) []core.Observation {
				res, err := s.(core.VerificationMethodRetriever).RetrieveVerificationMethod(ctx, rv.VMIdentifier, rv.Relationship, CloneOptions(rv.Options))
				return JudgeRetrieval(rv, res, err)
			}),
		})
	}
	return out
}

// JudgeRetrieval turns a retrieval result into observations, one per
// statement of each expectation. A call the adapter could not make is
// ERROR for every statement.
func JudgeRetrieval(rv Retrieval, res core.RetrievalResult, err error) []core.Observation {
	var r Recorder
	opts, _ := json.Marshal(rv.Options)
	input := fmt.Sprintf("retrieveVerificationMethod(%s, %s, %s)", rv.VMIdentifier, rv.Relationship, opts)
	if err != nil {
		r.All(rv.Statements(), core.Error, input, "the subject returned no result: "+err.Error())
		return r.Observations()
	}
	for _, e := range rv.Expect {
		check, ok := RetrievalChecks[e.Check]
		if !ok {
			r.All(e.Statements, core.Error, input, "unknown check "+e.Check)
			continue
		}
		pass, exp, obs, note := check(Retrieved{Retrieval: rv, Result: res}, e.Value)
		if !pass && obs == "" {
			obs = summarizeRetrieval(res)
		}
		r.Judge(e.Statements, input, pass, e.Check+": "+exp, obs, joinNotes(e.Partial, note))
	}
	return r.Observations()
}

// ValidateRetrievals checks a retrieval file: every scenario has a case
// id, a verification method identifier and expectations, and every
// expectation names a known check and at least one statement.
func ValidateRetrievals(f RetrievalFile) error {
	var errs []error
	for i, rv := range f.Scenarios {
		where := fmt.Sprintf("retrieval %d (%s)", i, rv.Case)
		if rv.Case == "" || rv.VMIdentifier == "" || len(rv.Expect) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs case, vmIdentifier and expect", where))
		}
		for _, e := range rv.Expect {
			if _, ok := RetrievalChecks[e.Check]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown check %q", where, e.Check))
			}
			if len(e.Statements) == 0 {
				errs = append(errs, fmt.Errorf("%s: check %s names no statement", where, e.Check))
			}
			if e.Check == "returnsMethod" && len(e.Value) == 0 {
				errs = append(errs, fmt.Errorf("%s: check returnsMethod needs a value", where))
			}
		}
	}
	return errors.Join(errs...)
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

func summarizeRetrieval(res core.RetrievalResult) string {
	var parts []string
	if res.VerificationMethod != nil {
		parts = append(parts, "verification method "+checks.Compact(res.VerificationMethod.Value()))
	}
	if res.Error != nil {
		parts = append(parts, fmt.Sprintf("error %q (%s)", res.Error.Type, res.Error.Detail))
	}
	if len(parts) == 0 {
		return "neither a verification method nor an error"
	}
	return strings.Join(parts, ", ")
}

// documentURL returns the vmIdentifier without its fragment: the
// controllerDocumentUrl of CID 1.0 §3.3.
func documentURL(vmIdentifier string) string {
	before, _, _ := strings.Cut(vmIdentifier, "#")
	return before
}

// absoluteIn resolves a reference found in the controller document against
// the document's DID; a value that cannot be resolved is returned as is.
func absoluteIn(docURL, ref string) string {
	did := baseDID(docURL)
	if out, err := checks.ResolveDIDReference(did, ref); err == nil {
		return out
	}
	return ref
}

// returned reports the method of a successful retrieval, or why there is
// none.
func returned(res core.RetrievalResult) (core.DocumentJSON, string) {
	switch {
	case res.Error != nil:
		return core.DocumentJSON{}, summarizeRetrieval(res)
	case res.VerificationMethod == nil:
		return core.DocumentJSON{}, "no verification method and no error"
	}
	return *res.VerificationMethod, ""
}

// checkReturnsMethod: the algorithm returns the verification method of
// the value, with relative id and controller values compared by their
// absolute URL values against the controller document URL.
func checkReturnsMethod(r Retrieved, v json.RawMessage) (bool, string, string, string) {
	docURL := documentURL(r.Retrieval.VMIdentifier)
	want := absoluteMethod(docURL, objectValue(v))
	got, why := returned(r.Result)
	if why != "" {
		return false, checks.Compact(want.Value()), why, ""
	}
	got = absoluteMethod(docURL, got)
	ok, at := checks.EqualJSON(got.Value(), want.Value())
	return ok, checks.Compact(want.Value()), fmt.Sprintf("%s (first difference at %q)", checks.Compact(got.Value()), at), ""
}

func absoluteMethod(docURL string, d core.DocumentJSON) core.DocumentJSON {
	out := core.DocumentJSON{Members: make([]core.Member, len(d.Members))}
	for i, m := range d.Members {
		if (m.Name == "id" || m.Name == "controller") && m.Value.Kind == core.KindString {
			m = core.M(m.Name, core.String(absoluteIn(docURL, m.Value.Str)))
		}
		out.Members[i] = m
	}
	return out
}

// checkReturnsIdentified: the algorithm returns a verification method
// whose id, as an absolute URL, is the vmIdentifier.
func checkReturnsIdentified(r Retrieved, _ json.RawMessage) (bool, string, string, string) {
	want := r.Retrieval.VMIdentifier
	got, why := returned(r.Result)
	if why != "" {
		return false, "a verification method with id " + want, why, ""
	}
	id, _ := StringMember(got, "id")
	abs := absoluteIn(documentURL(want), id)
	return abs == want, "a verification method whose absolute id is " + want, fmt.Sprintf("id %q (absolute %q)", id, abs), ""
}

// checkRaisesError: the algorithm raises an error and returns no
// verification method. The value, when present, is the error the
// statement recommends conveying; the observation reports the type the
// subject conveyed, which the statement's SHOULD leaves unjudged.
func checkRaisesError(r Retrieved, v json.RawMessage) (bool, string, string, string) {
	res := r.Result
	ok := res.Error != nil && res.VerificationMethod == nil
	note := ""
	if len(v) > 0 && res.Error != nil {
		want := stringsValue(v)[0]
		verdict := "differs from"
		if res.Error.Type == want || strings.HasSuffix(res.Error.Type, "#"+want) {
			verdict = "matches"
		}
		note = fmt.Sprintf("the conveyed error type %q %s the recommended %s, which is not judged", res.Error.Type, verdict, want)
	}
	return ok, "an error and no verification method", summarizeRetrieval(res), note
}
