package sage

import (
	"encoding/json"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualRetrievalAndProblems(t *testing.T) {
	s := &Subject{}
	rows, _ := sageprojection.Fixtures()
	record := rows[0]
	for _, ref := range []string{"#sign", "#agree", "#unknown", "zero"} {
		q := sageresolution.RetrievalRequest{Reference: record.DID + ref, Purpose: "authentication"}
		if ref == "zero" {
			q.Reference = ""
			q.Zero = true
		}
		r, e := s.InspectRetrieval(t.Context(), record, q)
		if e != nil || r.CaptureError != "" {
			t.Fatal(r, e)
		}
		if ref == "#sign" {
			if r.Error != "" || len(r.Method) == 0 || len(r.Calls) != 1 {
				t.Fatal(r)
			}
		} else {
			var problem map[string]any
			if r.Error == "" || json.Unmarshal(r.Problem, &problem) != nil || problem["type"] == "" {
				t.Fatal(r)
			}
		}
	}
	for _, q := range []sageresolution.RetrievalRequest{{Zero: true, Reference: "other", Purpose: "authentication"}, {Purpose: "bad"}, {Reference: "bad", Purpose: "authentication"}, {Zero: true, Purpose: "authentication", Options: map[string]any{"accept": false}}} {
		if _, e := s.InspectRetrieval(t.Context(), record, q); e == nil {
			t.Fatal("invalid adapter input", q)
		}
	}
	record.DID = "bad"
	if _, e := s.InspectRetrieval(t.Context(), record, sageresolution.RetrievalRequest{Zero: true, Purpose: "authentication"}); e == nil {
		t.Fatal("invalid record")
	}
}

func TestRetrievalCapturePreservesUnserializableOptions(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	rec, e := resolutionRecord(rows[0])
	if e != nil {
		t.Fatal(e)
	}
	r, e := didsage.NewResolver(resolutionSource{rec, ""}, consumer.New(), producer.New())
	if e != nil {
		t.Fatal(e)
	}
	out := sageresolution.RetrievalResult{}
	observed := retrievalDereferencer{r, &out}
	u, _ := did.ParseURL(rows[0].DID)
	actual := observed.Dereference(t.Context(), u, resolution.DereferenceOptions{Extra: map[string]any{"invalid": func() {}}})
	if out.CaptureError == "" || len(out.Calls) != 1 || actual.ContentStream != nil {
		t.Fatal("capture or actual refusal lost", out, actual)
	}
}
