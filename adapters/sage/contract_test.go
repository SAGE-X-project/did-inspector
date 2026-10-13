package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualNativeContracts(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	ids := map[string]bool{}
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/native-contract-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			ids[o.Statement] = true
			if o.Verdict != core.Pass {
				t.Fatal(c.ID, o)
			}
			var out sageresolution.ContractResult
			if json.Unmarshal([]byte(o.Observed), &out) != nil || out.Operation == "" || len(out.Options) == 0 {
				t.Fatal("lost actual entry")
			}
			if strings.Contains(c.ID, "zero-") && out.Result.HasContent {
				t.Fatal("zero native input accepted")
			}
		}
	}
	if count != 23 || len(ids) != 23 {
		t.Fatal(count, len(ids))
	}
}
func TestNativeContractAdapterBoundaries(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	for _, q := range []sageresolution.ContractRequest{{Request: sageresolution.Request{Function: "other"}}, {Zero: true, Request: sageresolution.Request{Function: "resolve", Input: rows[0].DID}}, {Request: sageresolution.Request{Function: "resolve", HTTP: &core.HTTPRequest{}}}, {Request: sageresolution.Request{Function: "resolve", NativeFunction: "resolve"}}, {Request: sageresolution.Request{Function: "resolve", Input: "invalid"}}, {Request: sageresolution.Request{Function: "dereference", Input: "invalid"}}} {
		if _, e := s.InspectContract(t.Context(), rows[0], q); e == nil {
			t.Fatal(q)
		}
	}
	bad := rows[0]
	bad.DID = "invalid"
	if _, e := s.InspectContract(t.Context(), bad, sageresolution.ContractRequest{Request: sageresolution.Request{Function: "resolve", Input: rows[0].DID}}); e == nil {
		t.Fatal("bad record")
	}
	for _, fn := range []string{"resolve", "dereference"} {
		q := sageresolution.ContractRequest{Request: sageresolution.Request{Function: fn, Input: rows[0].DID, Options: map[string]any{"accept": true}}}
		out, e := s.InspectContract(t.Context(), rows[0], q)
		if e != nil || out.CaptureError == "" || out.Result.HasContent || len(out.Problem) == 0 {
			t.Fatal("unserializable shadow retained", e, out)
		}
	}
}
