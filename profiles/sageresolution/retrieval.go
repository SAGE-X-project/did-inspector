package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"reflect"
	"strings"
)

type retrievalFixture struct {
	Name       string                `json:"name"`
	Record     sageprojection.Record `json:"record"`
	Request    RetrievalRequest      `json:"request"`
	Problem    string                `json:"problem,omitempty"`
	Statements []string              `json:"statements"`
}

func retrievalFixtures(record sageprojection.Record) []retrievalFixture {
	positive := []string{"cid10#retrieve-verification-method.2", "cid10#retrieve-verification-method.4", "cid10#retrieve-verification-method.7", "cid10#retrieve-verification-method.12"}
	errors := []string{"cid10#processing-errors.2", "cid10#processing-errors.3", "cid10#processing-errors.4"}
	zero := append([]string{"cid10#retrieve-verification-method.1"}, errors...)
	relationship := append([]string{"cid10#retrieve-verification-method.11"}, errors...)
	missing := append([]string{"cid10#retrieve-verification-method.8"}, errors...)
	return []retrievalFixture{
		{"authorized", record, RetrievalRequest{Reference: record.DID + "#sign", Purpose: "authentication"}, "", positive},
		{"authorized-options", record, RetrievalRequest{Reference: record.DID + "#sign", Purpose: "authentication", Options: map[string]any{"accept": "application/did"}}, "", positive},
		{"typed-zero", record, RetrievalRequest{Zero: true, Purpose: "authentication"}, "INVALID_VERIFICATION_METHOD_URL", zero},
		{"unauthorized-purpose", record, RetrievalRequest{Reference: record.DID + "#agree", Purpose: "authentication"}, "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD", relationship},
		{"missing-method", record, RetrievalRequest{Reference: record.DID + "#unknown", Purpose: "authentication"}, "INVALID_VERIFICATION_METHOD", missing},
	}
}
func retrievalVerdict(f retrievalFixture, out RetrievalResult) core.Verdict {
	q := f.Request
	if out.Operation != "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod" || out.Reference != q.Reference || out.Purpose != q.Purpose || out.CaptureError != "" || out.Clock != 1800000000 {
		return core.Error
	}
	if q.Zero {
		if len(out.Calls) != 0 {
			return core.Fail
		}
	} else {
		if len(out.Calls) != 1 {
			return core.Error
		}
		call := out.Calls[0]
		var options map[string]any
		if json.Unmarshal(call.Options, &options) != nil {
			return core.Error
		}
		expected := q.Options
		if expected == nil {
			expected = map[string]any{}
		}
		if call.Input != f.Record.DID || !reflect.DeepEqual(options, expected) {
			return core.Fail
		}
		r := call.Result
		if !r.HasContent || r.ContentKind != "document" || r.ReturnedID != f.Record.DID {
			return core.Error
		}
	}
	if f.Problem != "" {
		if out.Error == "" || len(out.Method) != 0 {
			return core.Fail
		}
		return core.Pass
	}
	if out.Error != "" || len(out.Problem) > 0 || out.ProblemSerializer != "" {
		return core.Fail
	}
	var method map[string]any
	var doc struct {
		ID      string           `json:"id"`
		Methods []map[string]any `json:"verificationMethod"`
		Auth    []string         `json:"authentication"`
	}
	if json.Unmarshal(out.Method, &method) != nil || json.Unmarshal(out.Calls[0].Result.Snapshot, &doc) != nil {
		return core.Error
	}
	if doc.ID != f.Record.DID || method["id"] != q.Reference || method["controller"] != f.Record.DID {
		return core.Fail
	}
	authorized := false
	for _, ref := range doc.Auth {
		if ref == q.Reference {
			authorized = true
		}
	}
	if !authorized {
		return core.Fail
	}
	for _, m := range doc.Methods {
		if m["id"] == q.Reference && reflect.DeepEqual(m, method) {
			return core.Pass
		}
	}
	return core.Fail
}
func judgeRetrieval(f retrievalFixture, out RetrievalResult, input string) []core.Observation {
	verdict := retrievalVerdict(f, out)
	raw, _ := json.Marshal(out)
	obs := unavailable(f.Statements, verdict, "Actual selected relying party with fresh SAGE document dereferencing. Passive pre-call primary URL/options, document snapshot, selected method and unchanged native problem object are preserved. Typed-zero tests actual invalid input, not adapter parser refusal. Explicit controls cover authorized selection, absent method and a method lacking the requested relationship. For mixed MUST-raise/SHOULD-type clauses the PASS covers mandatory refusal; the original advisory type is diagnostic, not a second mandatory condition. CID problem type and title/detail have separate statement verdicts. Selected problem titles/details are checked against reviewed human-readable error controls, not inferred solely from nonempty strings. No forged controller/id, full recursive fragment walk, cryptographic use, history or authority proof is claimed.")
	for i := range obs {
		if obs[i].Statement == "cid10#processing-errors.2" && verdict == core.Pass {
			obs[i].Verdict = retrievalProblemType(out)
		}
		if obs[i].Statement == "cid10#processing-errors.3" || obs[i].Statement == "cid10#processing-errors.4" {
			if verdict == core.Pass {
				obs[i].Verdict = retrievalAdvisory(f, out, obs[i].Statement)
			}
		}
		obs[i].Input = input
		obs[i].Observed = string(raw)
		obs[i].Expected = "Actual primary-URL/options and exact document-selected method, or native refusal and original CID problem type/title/detail"
	}
	return obs
}
func appendRetrievalCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range retrievalFixtures(rows[0]) {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/library-retrieval-" + f.Name, Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(RetrievalSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no actual relying-party observer", string(input), nil)
			}
			out, e := s.InspectRetrieval(ctx, f.Record, f.Request)
			if e != nil {
				return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
			}
			return judgeRetrieval(f, out, string(input))
		}})
	}
}

// Human-readable recommendations are judged separately from mandatory refusal
// and type behavior. Unreviewed nonempty prose is not automatically invalid.
func retrievalAdvisory(f retrievalFixture, out RetrievalResult, id string) core.Verdict {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(out.Problem, &p) != nil {
		return core.Error
	}
	if id == "cid10#processing-errors.3" {
		if p.Title == "" {
			return core.Fail
		}
		titles := map[string]string{"INVALID_VERIFICATION_METHOD_URL": "Invalid verification method URL", "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD": "Invalid relationship for verification method", "INVALID_VERIFICATION_METHOD": "Invalid verification method"}
		if p.Title == titles[f.Problem] {
			return core.Pass
		}
		return core.NotSupported
	}
	if p.Detail == "" {
		return core.Fail
	}
	expected := ""
	switch f.Problem {
	case "INVALID_VERIFICATION_METHOD_URL":
		expected = `"" is not an absolute DID URL with a fragment`
	case "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD":
		expected = f.Request.Reference + " is not in " + f.Request.Purpose
	case "INVALID_VERIFICATION_METHOD":
		expected = "no verification method has the id " + f.Request.Reference
	}
	if p.Detail == expected {
		return core.Pass
	}
	return core.NotSupported
}

func retrievalProblemType(out RetrievalResult) core.Verdict {
	if out.ProblemSerializer != "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)" {
		return core.Error
	}
	var p struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(out.Problem, &p) != nil {
		return core.Error
	}
	known := map[string]bool{"INVALID_VERIFICATION_METHOD_URL": true, "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT": true, "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID": true, "INVALID_VERIFICATION_METHOD": true, "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD": true}
	code, ok := strings.CutPrefix(p.Type, "https://w3id.org/security#")
	if !ok || !known[code] {
		return core.Fail
	}
	return core.Pass
}
