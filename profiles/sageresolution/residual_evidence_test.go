package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func residualControl(kind string) []ClientResult {
	out := []ClientResult{}
	for i, q := range residualRequests(kind) {
		v := clientControl(clientFixture{Request: q})
		var reply map[string]json.RawMessage
		_ = json.Unmarshal(q.Reply, &reply)
		v.Result.Metadata = reply["didResolutionMetadata"]
		v.Result.ContentMetadata = reply["didDocumentMetadata"]
		v.Consumer[0].Require = "unknown"
		v.Consumer[0].Expected = "unknown"
		v.Consumer[0].Version = "1.1"
		v.Consumer[0].JSONLD = true
		v.Consumer[0].Model = []byte(residualModel)
		v.Consumer[0].Entries = []byte(`{"@context":"https://www.w3.org/ns/did/v1.1"}`)
		if kind == residualProxy && i == 0 {
			v.Consumer[0].MediaType = "application/json"
			v.Result.Metadata = []byte(`{"contentType":"application/did"}`)
		}
		out = append(out, v)
	}
	return out
}
func TestResidualJudgment(t *testing.T) {
	for _, kind := range []string{residualHistory, residualProxy} {
		assert := func(v []ClientResult, want core.Verdict) {
			t.Helper()
			for _, o := range judgeResidual(kind, v, "unit") {
				if o.Verdict != want {
					t.Fatalf("%s: %+v", kind, o)
				}
			}
		}
		assert(residualControl(kind), core.Pass)
		assert(nil, core.Error)
		for _, change := range []func(*ClientResult){
			func(v *ClientResult) { v.Endpoint = "%" }, func(v *ClientResult) { v.Endpoint = "https://outside.example/1.0/identifiers/" },
			func(v *ClientResult) { v.Request.Post = true }, func(v *ClientResult) { v.Operation = "other" }, func(v *ClientResult) { v.ServerRole = "other" }, func(v *ClientResult) { v.ServerTLS = false }, func(v *ClientResult) { v.ServerCalls = 0 }, func(v *ClientResult) { v.Wire = nil }, func(v *ClientResult) { v.Native = []ClientInvocation{{}} }, func(v *ClientResult) { v.Consumer = nil },
			func(v *ClientResult) { v.Wire[0].CaptureError = "lost" }, func(v *ClientResult) { v.Wire[0].Method = "POST" }, func(v *ClientResult) { v.Wire[0].URL = "other" }, func(v *ClientResult) { v.Wire[0].Accept = "other" }, func(v *ClientResult) { v.Wire[0].ContentType = "other" }, func(v *ClientResult) { v.Wire[0].Body = []byte(`{}`) }, func(v *ClientResult) { v.Consumer[0].Operation = "other" }, func(v *ClientResult) { v.Consumer[0].MediaType = "other" }, func(v *ClientResult) { v.Consumer[0].Input = nil }, func(v *ClientResult) { v.Consumer[0].Require = "1.1" }, func(v *ClientResult) { v.Consumer[0].Expected = "1.0" }, func(v *ClientResult) { v.Consumer[0].Strict = true }, func(v *ClientResult) { v.Consumer[0].CaptureError = "lost"; v.Consumer[0].Error = "refused" }, func(v *ClientResult) { v.Result.Metadata = []byte(`{`) }, func(v *ClientResult) { v.Result.ContentMetadata = []byte(`[]`) },
		} {
			v := residualControl(kind)
			change(&v[0])
			assert(v, core.Error)
		}
		for _, change := range []func(*ClientResult){func(v *ClientResult) { v.Consumer[0].Error = "refused" }, func(v *ClientResult) { v.Consumer[0].Version = "1.0" }, func(v *ClientResult) { v.Consumer[0].JSONLD = false }, func(v *ClientResult) { v.Consumer[0].Model = nil }, func(v *ClientResult) { v.Consumer[0].Entries = nil }, func(v *ClientResult) { v.Result.HasContent = false }, func(v *ClientResult) { v.Result.ReturnedID = "other" }, func(v *ClientResult) {
			v.Result.Metadata = []byte(`{"error":{"type":"internalError"},"contentType":"application/did"}`)
		}} {
			v := residualControl(kind)
			change(&v[0])
			assert(v, core.NotSupported)
		}
	}
	for _, field := range []string{"nextUpdate", "nextVersionId"} {
		v := residualControl(residualHistory)
		var md map[string]any
		_ = json.Unmarshal(v[0].Result.ContentMetadata, &md)
		delete(md, field)
		v[0].Result.ContentMetadata, _ = json.Marshal(md)
		got := judgeResidual(residualHistory, v, "unit")
		index := 0
		if field == "nextVersionId" {
			index = 1
		}
		if got[index].Verdict != core.NotSupported || got[1-index].Verdict != core.Pass {
			t.Fatal(got)
		}
	}
	v := residualControl(residualHistory)
	v[0].Result.ContentMetadata = []byte(`{"versionId":"other"}`)
	if judgeResidual(residualHistory, v, "unit")[0].Verdict != core.NotSupported {
		t.Fatal("wrong version")
	}
	v = residualControl(residualProxy)
	v[0].Result.Metadata = []byte(`{}`)
	if judgeResidual(residualProxy, v, "unit")[0].Verdict != core.NotSupported {
		t.Fatal("missing addition")
	}
	// Absence is not mandatory for the two diagnostic MAY controls.
	v = residualControl(residualHistory)
	v[1].Result.ContentMetadata = []byte(`{"versionId":"8","nextVersionId":"9"}`)
	if judgeResidual(residualHistory, v, "unit")[0].Verdict != core.Pass {
		t.Fatal("overconstrained MAY")
	}
}

type residualMock struct {
	noOperation
	kind          string
	calls, failAt int
}

func (s *residualMock) InspectClient(_ context.Context, _ sageprojection.Record, _ ClientRequest) (ClientResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return ClientResult{}, errors.New("lost")
	}
	return residualControl(s.kind)[s.calls-1], nil
}
func TestResidualDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-core-1.0"}
	appendResidualCases(&p, records)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendResidualCases(&p, records)
	if len(p.Cases) != 2 {
		t.Fatal("cases")
	}
	for i, kind := range []string{residualHistory, residualProxy} {
		c := p.Cases[i]
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		for _, tt := range []struct {
			s core.Subject
			v core.Verdict
		}{{&residualMock{kind: kind}, core.Pass}, {&residualMock{kind: kind, failAt: 1}, core.Error}, {&residualMock{kind: kind, failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tt.s) {
				if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
					t.Fatal(o)
				}
			}
		}
	}
}
