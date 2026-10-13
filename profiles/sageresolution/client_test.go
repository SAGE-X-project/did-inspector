package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func clientControl(f clientFixture) ClientResult {
	q := f.Request
	ep := "https://127.0.0.1:43210/1.0/identifiers/"
	ident := q.Request.Input
	if (!q.Post && len(q.Request.Options) > 0) || q.Request.Function == "dereference" {
		ident = percentIdentifier(ident)
	}
	accept := q.Request.Accept
	if accept == "" {
		accept = "application/did-resolution"
		if q.Request.Function == "dereference" {
			accept = "application/did-url-dereferencing"
		}
	}
	w := ClientWire{URL: ep + ident, Method: "GET", Accept: accept}
	if q.Post {
		w.Method = "POST"
		if len(q.Request.Options) > 0 {
			w.Body, _ = json.Marshal(q.Request.Options)
			w.ContentType = "application/json"
		}
	} else {
		for k, v := range q.Request.Options {
			w.URL += "?" + k + "=" + fmt.Sprint(v)
		}
	}
	out := ClientResult{Operation: "github.com/sage-x-project/did-go/resolution/universal.Client." + q.Request.Function, Request: q, Endpoint: ep, Wire: []ClientWire{w}, ServerCalls: 1, ServerTLS: true, ServerRole: "SAGE handler with explicit fixture Source"}
	if len(q.Reply) > 0 {
		var reply struct {
			Metadata struct {
				ContentType string `json:"contentType"`
			} `json:"didResolutionMetadata"`
			Document json.RawMessage `json:"didDocument"`
		}
		_ = json.Unmarshal(q.Reply, &reply)
		v := "1.1"
		if reply.Metadata.ContentType == "application/did+json" {
			v = "1.0"
		}
		out.ServerRole = "controlled client response fixture; not SAGE server output"
		out.Consumer = []ConsumptionCapture{{Operation: pipelineConsumer, MediaType: reply.Metadata.ContentType, Version: v, Input: reply.Document}}
		out.Result.HasContent = true
		out.Result.ReturnedID = q.Request.Input
	}
	return out
}
func TestClientBranchControlsAndMutations(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	fixtures := clientFixtures(records[0])
	if len(fixtures) != 18 {
		t.Fatal(len(fixtures))
	}
	for _, f := range fixtures {
		if v := clientWireVerdict(f, clientControl(f)); v != core.Pass {
			t.Fatal(f.Name, v)
		}
		for _, change := range []func(*ClientResult){func(r *ClientResult) { r.Operation = "manual request" }, func(r *ClientResult) { r.Request.Request.Input = "other" }, func(r *ClientResult) { r.Wire = nil }, func(r *ClientResult) { r.ServerCalls = 0 }, func(r *ClientResult) { r.ServerTLS = false }, func(r *ClientResult) { r.Endpoint = "http://127.0.0.1:42/1.0/identifiers/" }, func(r *ClientResult) { r.Endpoint = "%zz" }, func(r *ClientResult) { r.Wire[0].URL = "%zz" }, func(r *ClientResult) { r.Wire[0].CaptureError = "lost" }, func(r *ClientResult) { r.Wire[0].URL = "https://outside.example/other" }, func(r *ClientResult) { r.Wire[0].URL += "#changed" }, func(r *ClientResult) { r.Wire[0].Method = "DELETE" }, func(r *ClientResult) { r.Wire[0].Accept = "*/*" }, func(r *ClientResult) { r.Wire[0].ContentType = "text/plain" }, func(r *ClientResult) { r.Wire[0].Body = []byte("{") }, func(r *ClientResult) { r.ServerRole = "other actor" }} {
			r := clientControl(f)
			change(&r)
			if clientWireVerdict(f, r) == core.Pass {
				t.Fatal("false PASS", f.Name)
			}
		}
		if len(f.Request.Reply) > 0 {
			for _, change := range []func(*ClientResult){func(r *ClientResult) { r.Consumer = nil }, func(r *ClientResult) { r.Consumer[0].Version = "wrong" }, func(r *ClientResult) { r.Consumer[0].MediaType = "application/json" }, func(r *ClientResult) { r.Consumer[0].Input = []byte("{}") }, func(r *ClientResult) { r.Consumer[0].Error = "refused" }, func(r *ClientResult) { r.Result.HasContent = false }} {
				r := clientControl(f)
				change(&r)
				if clientWireVerdict(f, r) == core.Pass {
					t.Fatal("false metadata PASS")
				}
			}
		}
		if len(f.Request.Request.Options) > 0 {
			r := clientControl(f)
			if f.Request.Post {
				r.Wire[0].Body = []byte(`{"accept":"application/did"}`)
			} else {
				r.Wire[0].URL += "&accept=application%2Fdid"
			}
			if clientWireVerdict(f, r) == core.Pass {
				t.Fatal("accept leaked into options")
			}
		}
	}
	if percentIdentifier("AZaz09-._~:/?#%") == "" {
		t.Fatal("encoding")
	}
	if percentIdentifier("did:sage:x:a#sign") != "did%3Asage%3Ax%3Aa%23sign" {
		t.Fatal("independent percent oracle")
	}
}

type clientMock struct {
	noOperation
	fail bool
}

func (s clientMock) InspectClient(_ context.Context, r sageprojection.Record, q ClientRequest) (ClientResult, error) {
	if s.fail {
		return ClientResult{}, errors.New("actual dispatch failed")
	}
	return clientControl(clientFixture{Record: r, Request: q}), nil
}
func TestClientProfileDispatch(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendClientCases(&p, rows)
		want := 18
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
			}{{clientMock{}, core.Pass}, {clientMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o)
					}
				}
			}
		}
	}
}
