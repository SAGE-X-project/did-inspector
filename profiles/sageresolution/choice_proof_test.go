package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func proofControl() []ClientResult {
	out := []ClientResult{}
	for _, q := range resolverProofRequests() {
		v := clientControl(clientFixture{Request: q})
		var reply map[string]json.RawMessage
		_ = json.Unmarshal(q.Reply, &reply)
		v.Result.Metadata = reply["didResolutionMetadata"]
		v.Consumer[0].Require = "unknown"
		v.Consumer[0].Expected = "unknown"
		out = append(out, v)
	}
	return out
}
func TestResolverProofCapability(t *testing.T) {
	if judgeResolverProof(proofControl(), "unit")[0].Verdict != core.Pass {
		t.Fatal("control")
	}
	if judgeResolverProof(nil, "unit")[0].Verdict != core.Error {
		t.Fatal("missing")
	}
	for _, change := range []func(*ClientResult){func(v *ClientResult) { v.Endpoint = "%" }, func(v *ClientResult) { v.Endpoint = "https://outside.example/1.0/identifiers/" }, func(v *ClientResult) { v.Request.Post = true }, func(v *ClientResult) { v.Operation = "other" }, func(v *ClientResult) { v.ServerRole = "other" }, func(v *ClientResult) { v.ServerTLS = false }, func(v *ClientResult) { v.ServerCalls = 2 }, func(v *ClientResult) { v.Wire = nil }, func(v *ClientResult) { v.Native = []ClientInvocation{{}} }, func(v *ClientResult) { v.Consumer = nil }, func(v *ClientResult) { v.Wire[0].CaptureError = "lost" }, func(v *ClientResult) { v.Wire[0].Method = "POST" }, func(v *ClientResult) { v.Wire[0].URL = "other" }, func(v *ClientResult) { v.Wire[0].Accept = "other" }, func(v *ClientResult) { v.Wire[0].ContentType = "other" }, func(v *ClientResult) { v.Wire[0].Body = []byte(`{}`) }, func(v *ClientResult) { v.Consumer[0].Operation = "other" }, func(v *ClientResult) { v.Consumer[0].MediaType = "other" }, func(v *ClientResult) { v.Consumer[0].Input = nil }, func(v *ClientResult) { v.Consumer[0].Require = "1.0" }, func(v *ClientResult) { v.Consumer[0].Expected = "1.0" }, func(v *ClientResult) { v.Consumer[0].Strict = true }, func(v *ClientResult) { v.Consumer[0].CaptureError = "lost" }, func(v *ClientResult) { v.Result.Metadata = []byte(`{`) }, func(v *ClientResult) { v.Result.Metadata = []byte(`[]`) }} {
		v := proofControl()
		change(&v[0])
		if judgeResolverProof(v, "unit")[0].Verdict != core.Error {
			t.Fatal(v)
		}
	}
	for _, change := range []func(*ClientResult){func(v *ClientResult) { v.Consumer[0].Error = "refused"; v.Consumer[0].CaptureError = "nil model" }, func(v *ClientResult) { v.Result.HasContent = false }, func(v *ClientResult) { v.Result.ReturnedID = "other" }, func(v *ClientResult) { v.Result.Metadata = []byte(`{}`) }, func(v *ClientResult) { v.Result.Metadata = []byte(`{"proof":[]}`) }} {
		v := proofControl()
		change(&v[0])
		if judgeResolverProof(v, "unit")[0].Verdict != core.NotSupported {
			t.Fatal(v)
		}
	}
	v := proofControl()
	v[0].Result.ContentMetadata = []byte(`{"deactivated":false}`)
	v[1].Result.Metadata = v[0].Result.Metadata
	if judgeResolverProof(v, "unit")[0].Verdict != core.Pass {
		t.Fatal("unrelated document metadata or absent control imposed extra obligation")
	}
}

type proofMock struct {
	noOperation
	calls, failAt int
}

func (s *proofMock) InspectClient(_ context.Context, _ sageprojection.Record, _ ClientRequest) (ClientResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return ClientResult{}, errors.New("lost")
	}
	return proofControl()[s.calls-1], nil
}
func TestResolverProofDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-core-1.0"}
	appendResolverProofCases(&p, records)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendResolverProofCases(&p, records)
	if len(p.Cases) != 1 {
		t.Fatal("cases")
	}
	c := p.Cases[0]
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		s core.Subject
		v core.Verdict
	}{{&proofMock{}, core.Pass}, {&proofMock{failAt: 1}, core.Error}, {&proofMock{failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
		for _, o := range c.Run(t.Context(), tt.s) {
			if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
}
