package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func expansionControl() []RoutingResult {
	v := []RoutingResult{}
	for _, enabled := range []bool{false, true} {
		q := expansionRequest(enabled)
		options := []byte(`{"accept":"application/did"}`)
		doc := expansionDocument
		if enabled {
			options = []byte(`{"accept":"application/did","expandRelativeUrls":true}`)
			doc = expansionExpected
		}
		read, _ := json.Marshal(map[string]any{"Data": expansionDocument, "ContentType": "application/did", "Metadata": map[string]any{}})
		v = append(v, RoutingResult{DriverInputs: []string{"did:example:123"}, DriverResults: [][]byte{read}, Request: q, Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve", ResolveInputs: []string{"did:example:123"}, ResolveOptions: [][]byte{options}, DriverOptions: [][]byte{[]byte(`{"MediaType":"application/did"}`)}, Options: options, DataModel: doc, Entries: []byte(`{}`), Result: Result{HasContent: true, ReturnedID: "did:example:123", Metadata: []byte(`{"contentType":"application/did"}`)}})
	}
	return v
}
func TestExpansionLiteralControlsAndGuards(t *testing.T) {
	for _, o := range judgeExpansion(expansionControl(), "input") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	if judgeExpansion(nil, "input")[0].Verdict != core.Error {
		t.Fatal("partial calls")
	}
	for _, change := range []func(*RoutingResult){func(r *RoutingResult) { r.Request.Request.Input = "other" }, func(r *RoutingResult) { r.Role = "other" }, func(r *RoutingResult) { r.Operation = "other" }, func(r *RoutingResult) { r.CaptureError = "lost" }, func(r *RoutingResult) { r.ResolveInputs = nil }, func(r *RoutingResult) { r.DriverOptions = nil }, func(r *RoutingResult) { r.ResolveOptions = nil }, func(r *RoutingResult) { r.Options = []byte(`{`) }, func(r *RoutingResult) { r.Options = []byte(`{}`) }, func(r *RoutingResult) { r.Result.Metadata = []byte(`{`) }, func(r *RoutingResult) { r.Entries = []byte(`{"extra":true}`) }, func(r *RoutingResult) { r.DataModel = []byte(`{`) }, func(r *RoutingResult) { r.Result.Metadata = []byte(`{"error":{}}`) }, func(r *RoutingResult) { r.Result.HasContent = false }, func(r *RoutingResult) { r.Result.ReturnedID = "other" }} {
		v := expansionControl()
		change(&v[1])
		for _, o := range judgeExpansion(v, "input") {
			if o.Statement != "res10-crd20261001#resolving-algorithm.17" && o.Verdict == core.Pass {
				t.Fatal("false expansion PASS")
			}
		}
	}
	v := expansionControl()
	v[1].DataModel = expansionDocument
	for _, o := range judgeExpansion(v, "input") {
		if o.Statement != "res10-crd20261001#resolving-algorithm.17" && o.Verdict != core.Fail {
			t.Fatal(o)
		}
	}
}

type expansionMock struct {
	noOperation
	fail bool
}

func (s expansionMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	if s.fail {
		return RoutingResult{}, errors.New("failed capture")
	}
	i := 0
	if q.Request.Options["expandRelativeUrls"] == true {
		i = 1
	}
	return expansionControl()[i], nil
}
func TestExpansionDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendExpansionCases(&p)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{expansionMock{}, core.Pass}, {expansionMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestDisabledExpansionIsDiagnosticAndReadIndependent(t *testing.T) {
	v := expansionControl()
	v[0].DataModel = []byte(`{"unrelated":"diagnostic"}`)
	for _, o := range judgeExpansion(v, "input") {
		if o.Verdict != core.Pass {
			t.Fatal("disabled output contaminated enabled clause", o)
		}
	}
	for _, o := range judgeMethodRead(v, "input") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	for _, change := range []func(*RoutingResult){func(r *RoutingResult) { r.DriverInputs = nil }, func(r *RoutingResult) { r.DriverInputs = []string{"other"} }, func(r *RoutingResult) { r.DriverResults = nil }, func(r *RoutingResult) { r.DriverResults[0] = []byte(`{`) }, func(r *RoutingResult) { r.DriverResults[0] = []byte(`{"Data":"!","ContentType":"application/did"}`) }, func(r *RoutingResult) { r.DriverOptions = nil }, func(r *RoutingResult) { r.DriverOptions[0] = []byte(`{`) }, func(r *RoutingResult) { r.DriverOptions[0] = []byte(`{}`) }, func(r *RoutingResult) { r.Request.Request.Input = "other" }, func(r *RoutingResult) { r.Role = "other" }, func(r *RoutingResult) { r.Operation = "other" }} {
		v := expansionControl()
		change(&v[1])
		if judgeMethodRead(v, "input")[0].Verdict != core.Error {
			t.Fatal("invalid method witness")
		}
	}
	if judgeMethodRead(nil, "input")[0].Verdict != core.Error {
		t.Fatal("missing read")
	}
	v = expansionControl()
	v[1].DriverResults[0] = []byte(`{"Data":"e30=","ContentType":"application/did"}`)
	if judgeMethodRead(v, "input")[0].Verdict != core.Fail {
		t.Fatal("wrong method output")
	}
	v = expansionControl()
	v[0].Options = []byte(`{"accept":"application/did","expandRelativeUrls":"false"}`)
	if judgeExpansion(v, "input")[0].Verdict != core.Error {
		t.Fatal("false string")
	}
	v = expansionControl()
	v[1].ResolveOptions[0] = []byte(`{}`)
	if judgeExpansion(v, "input")[0].Verdict != core.Error {
		t.Fatal("inconsistent call options")
	}
}

func TestExpansionURLVerdictsIgnoreUnrelatedMaterial(t *testing.T) {
	v := expansionControl()
	var d map[string]any
	_ = json.Unmarshal(v[1].DataModel, &d)
	d["verificationMethod"].([]any)[0].(map[string]any)["publicKeyJwk"].(map[string]any)["x"] = "unrelated diagnostic change"
	v[1].DataModel, _ = json.Marshal(d)
	for _, o := range judgeExpansion(v, "input") {
		wanted := core.Pass
		if o.Statement == "res10-crd20261001#resolving-algorithm.34" {
			wanted = core.Fail
		}
		if o.Verdict != wanted {
			t.Fatal("unrelated property contaminated URL rule", o)
		}
	}
	for _, literal := range []string{`{}`, `{"verificationMethod":true}`, `{"verificationMethod":[]}`, `{"verificationMethod":[{"id":42}]}`} {
		value, _ := core.ParseJSON([]byte(literal))
		if expansionURLsCorrect(value) {
			t.Fatal("bad URL witness")
		}
	}
}
