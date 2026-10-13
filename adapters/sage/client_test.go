package sage

import (
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualClientTLSRequests(t *testing.T) {
	s := &Subject{}
	rows, _ := sageprojection.Fixtures()
	record := rows[0]
	for _, fn := range []string{"resolve", "dereference"} {
		for _, post := range []bool{false, true} {
			q := sageresolution.ClientRequest{Request: sageresolution.Request{Function: fn, Input: record.DID}, Post: post}
			if fn == "dereference" {
				q.Request.Input += "#sign"
				q.Request.Options = map[string]any{"verificationRelationship": "authentication"}
			} else {
				q.Request.Options = map[string]any{"noCache": true}
			}
			r, e := s.InspectClient(t.Context(), record, q)
			if e != nil || len(r.Wire) != 1 || r.ServerCalls != 1 || !r.ServerTLS || !r.Result.HasContent || r.Wire[0].CaptureError != "" {
				t.Fatal(r, e)
			}
		}
	}
	for _, q := range []sageresolution.ClientRequest{{Request: sageresolution.Request{Function: "bad"}}, {Request: sageresolution.Request{Function: "resolve", Input: "bad"}}, {Request: sageresolution.Request{Function: "dereference", Input: "bad"}}} {
		if _, e := s.InspectClient(t.Context(), record, q); e == nil {
			t.Fatal("invalid dispatch")
		}
	}
	record.DID = "bad"
	if _, e := s.InspectClient(t.Context(), record, sageresolution.ClientRequest{Request: sageresolution.Request{Function: "resolve"}}); e == nil {
		t.Fatal("invalid record")
	}
}
