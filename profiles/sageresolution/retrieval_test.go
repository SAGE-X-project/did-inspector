package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func retrievalControl(f retrievalFixture) RetrievalResult {
	q := f.Request
	out := RetrievalResult{Operation: "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod", Clock: 1800000000, Reference: q.Reference, Purpose: q.Purpose, Calls: []RetrievalCall{}}
	if !q.Zero {
		options := q.Options
		if options == nil {
			options = map[string]any{}
		}
		data, _ := json.Marshal(options)
		snapshot := []byte(`{"id":"` + f.Record.DID + `","verificationMethod":[{"id":"` + f.Record.DID + `#sign","controller":"` + f.Record.DID + `","type":"JsonWebKey"}],"authentication":["` + f.Record.DID + `#sign"]}`)
		out.Calls = []RetrievalCall{{Input: f.Record.DID, Options: data, Result: Result{HasContent: true, ContentKind: "document", ReturnedID: f.Record.DID, Snapshot: snapshot}}}
	}
	if f.Problem != "" {
		title := map[string]string{"INVALID_VERIFICATION_METHOD_URL": "Invalid verification method URL", "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD": "Invalid relationship for verification method", "INVALID_VERIFICATION_METHOD": "Invalid verification method"}[f.Problem]
		detail := "no verification method has the id " + q.Reference
		if f.Problem == "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD" {
			detail = q.Reference + " is not in " + q.Purpose
		}
		if q.Zero {
			detail = `"" is not an absolute DID URL with a fragment`
		}
		out.Error = "opaque native error"
		out.Problem, _ = json.Marshal(map[string]string{"type": "https://w3id.org/security#" + f.Problem, "title": title, "detail": detail})
		out.ProblemSerializer = "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
	} else {
		out.Method = []byte(`{"id":"` + q.Reference + `","controller":"` + f.Record.DID + `","type":"JsonWebKey"}`)
	}
	return out
}
func TestRetrievalControlsAndMutations(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, f := range retrievalFixtures(records[0]) {
		if v := retrievalVerdict(f, retrievalControl(f)); v != core.Pass {
			t.Fatal(f.Name, v)
		}
		for _, change := range []func(*RetrievalResult){func(r *RetrievalResult) { r.Operation = "other" }, func(r *RetrievalResult) { r.Reference = "other" }, func(r *RetrievalResult) { r.Purpose = "keyAgreement" }, func(r *RetrievalResult) { r.CaptureError = "lost" }, func(r *RetrievalResult) { r.Clock++ }} {
			r := retrievalControl(f)
			change(&r)
			if retrievalVerdict(f, r) == core.Pass {
				t.Fatal("attribution lost")
			}
		}
		if f.Request.Zero {
			r := retrievalControl(f)
			r.Calls = []RetrievalCall{{}}
			if retrievalVerdict(f, r) == core.Pass {
				t.Fatal("invalid URL dereferenced")
			}
		} else {
			for _, change := range []func(*RetrievalResult){func(r *RetrievalResult) { r.Calls = nil }, func(r *RetrievalResult) { r.Calls[0].Input += "#sign" }, func(r *RetrievalResult) { r.Calls[0].Options = []byte("{") }, func(r *RetrievalResult) { r.Calls[0].Options = []byte(`{"accept":"other"}`) }, func(r *RetrievalResult) { r.Calls[0].Result.HasContent = false }} {
				r := retrievalControl(f)
				change(&r)
				if retrievalVerdict(f, r) == core.Pass {
					t.Fatal("document boundary lost")
				}
			}
		}
		if f.Problem != "" {
			for _, change := range []func(*RetrievalResult){func(r *RetrievalResult) { r.Error = "" }, func(r *RetrievalResult) { r.Method = []byte("{}") }, func(r *RetrievalResult) { r.ProblemSerializer = "synthesized" }, func(r *RetrievalResult) { r.Problem = []byte("{") }, func(r *RetrievalResult) {
				r.Problem = []byte(`{"type":"https://w3id.org/security#OTHER","title":"other","detail":"other"}`)
			}, func(r *RetrievalResult) {
				var m map[string]any
				_ = json.Unmarshal(r.Problem, &m)
				m["type"] = "generic"
				r.Problem, _ = json.Marshal(m)
			}} {
				r := retrievalControl(f)
				change(&r)
				allPass := true
				for _, o := range judgeRetrieval(f, r, "input") {
					if o.Verdict != core.Pass {
						allPass = false
					}
				}
				if allPass {
					t.Fatal("problem evidence lost")
				}
			}
		} else {
			for _, change := range []func(*RetrievalResult){func(r *RetrievalResult) { r.Error = "refused" }, func(r *RetrievalResult) { r.Problem = []byte("{}") }, func(r *RetrievalResult) { r.Method = []byte("{") }, func(r *RetrievalResult) { r.Calls[0].Result.Snapshot = []byte(`{"id":"other"}`) }, func(r *RetrievalResult) {
				r.Calls[0].Result.Snapshot = []byte(`{"id":"` + f.Record.DID + `","authentication":[]}`)
			}, func(r *RetrievalResult) { r.Method = []byte(`{"id":"other","controller":"other"}`) }, func(r *RetrievalResult) {
				var m map[string]any
				_ = json.Unmarshal(r.Method, &m)
				m["extra"] = "changed"
				r.Method, _ = json.Marshal(m)
			}} {
				r := retrievalControl(f)
				change(&r)
				if retrievalVerdict(f, r) == core.Pass {
					t.Fatal("selected method evidence lost")
				}
			}
		}
	}
}

func TestRetrievalRecommendationsStaySeparate(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, f := range retrievalFixtures(records[0]) {
		if f.Problem == "" {
			continue
		}
		for _, field := range []string{"title", "detail"} {
			for _, value := range []string{"", "unreviewed human description"} {
				r := retrievalControl(f)
				var p map[string]any
				_ = json.Unmarshal(r.Problem, &p)
				p[field] = value
				r.Problem, _ = json.Marshal(p)
				if retrievalVerdict(f, r) != core.Pass {
					t.Fatal("advisory polluted required type/refusal")
				}
				id := "cid10#processing-errors.3"
				if field == "detail" {
					id = "cid10#processing-errors.4"
				}
				want := core.NotSupported
				if value == "" {
					want = core.Fail
				}
				if retrievalAdvisory(f, r, id) != want {
					t.Fatal("prose recommendation")
				}
				obs := judgeRetrieval(f, r, "input")
				for _, o := range obs {
					if o.Statement == id && o.Verdict != want {
						t.Fatal(o)
					}
					if o.Statement == "cid10#processing-errors.2" && o.Verdict != core.Pass {
						t.Fatal("type polluted")
					}
				}
			}
		}
	}
	if retrievalAdvisory(retrievalFixture{}, RetrievalResult{Problem: []byte("{")}, "cid10#processing-errors.3") != core.Error {
		t.Fatal("malformed problem")
	}
}

type retrievalMock struct {
	noOperation
	fail bool
}

func (s retrievalMock) InspectRetrieval(_ context.Context, r sageprojection.Record, q RetrievalRequest) (RetrievalResult, error) {
	if s.fail {
		return RetrievalResult{}, errors.New("adapter failed")
	}
	for _, f := range retrievalFixtures(r) {
		a, _ := json.Marshal(q)
		b, _ := json.Marshal(f.Request)
		if string(a) == string(b) {
			return retrievalControl(f), nil
		}
	}
	return RetrievalResult{}, errors.New("unknown fixture")
}
func TestRetrievalDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendRetrievalCases(&p, records)
		want := 5
		if name == "did-core-1.0" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{retrievalMock{}, core.Pass}, {retrievalMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestCIDTypeDoesNotTurnAdvisoryCodeIntoMandatoryFailure(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	f := retrievalFixtures(records[0])[2]
	r := retrievalControl(f)
	var p map[string]any
	_ = json.Unmarshal(r.Problem, &p)
	p["type"] = "https://w3id.org/security#INVALID_VERIFICATION_METHOD"
	r.Problem, _ = json.Marshal(p)
	if retrievalVerdict(f, r) != core.Pass || retrievalProblemType(r) != core.Pass {
		t.Fatal("valid native CID type polluted mandatory refusal")
	}
	p["type"] = "https://w3id.org/did#INVALID_DID_URL"
	r.Problem, _ = json.Marshal(p)
	if retrievalVerdict(f, r) != core.Pass || retrievalProblemType(r) != core.Fail {
		t.Fatal("namespace failure not isolated")
	}
}
