package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func proxyControl() ClientResult {
	r, _ := parse([]byte(proxyReply))
	md, _ := r.Get("didResolutionMetadata")
	dm, _ := r.Get("didDocumentMetadata")
	a, _ := json.Marshal(md)
	b, _ := json.Marshal(dm)
	return ClientResult{Operation: "github.com/sage-x-project/did-go/resolution/universal.Client.resolve", Request: proxyRequest(), ServerRole: "controlled client response fixture; not SAGE server output", Endpoint: "https://127.0.0.1:1234/1.0/identifiers/", ServerTLS: true, ServerCalls: 1, Wire: []ClientWire{{Method: "GET", URL: "https://127.0.0.1:1234/1.0/identifiers/" + policyDID, Accept: "application/did"}}, Consumer: []ConsumptionCapture{{}}, Result: Result{Metadata: a, ContentMetadata: b, HasContent: true, ReturnedID: policyDID}}
}
func TestProxyPreservesBothMetadataMaps(t *testing.T) {
	if judgeProxy(proxyControl(), "input")[0].Verdict != core.Pass {
		t.Fatal("literal control")
	}
	for _, field := range []string{"metadata", "content_metadata"} {
		v := proxyControl()
		if field == "metadata" {
			v.Result.Metadata = []byte(`{"contentType":"application/did"}`)
		} else {
			v.Result.ContentMetadata = []byte(`{}`)
		}
		if judgeProxy(v, "input")[0].Verdict != core.Fail {
			t.Fatal("lost metadata")
		}
	}
	for _, change := range []func(*ClientResult){func(v *ClientResult) { v.Operation = "other" }, func(v *ClientResult) { v.Request.Request.Input = "other" }, func(v *ClientResult) { v.ServerRole = "SAGE" }, func(v *ClientResult) { v.ServerTLS = false }, func(v *ClientResult) { v.ServerCalls = 2 }, func(v *ClientResult) { v.Wire = nil }, func(v *ClientResult) { v.Consumer = nil }, func(v *ClientResult) { v.Native = []ClientInvocation{{}} }, func(v *ClientResult) { v.Endpoint = "bad" }, func(v *ClientResult) { v.Endpoint = "https://external.example/" }, func(v *ClientResult) { v.Wire[0].CaptureError = "lost" }, func(v *ClientResult) { v.Wire[0].Method = "POST" }, func(v *ClientResult) { v.Consumer[0].CaptureError = "lost" }, func(v *ClientResult) { v.Consumer[0].Error = "refused" }, func(v *ClientResult) { v.Result.HasContent = false }, func(v *ClientResult) { v.Result.ReturnedID = "other" }, func(v *ClientResult) { v.Result.Metadata = []byte(`{`) }, func(v *ClientResult) { v.Result.ContentMetadata = []byte(`{`) }} {
		v := proxyControl()
		change(&v)
		if judgeProxy(v, "input")[0].Verdict != core.Error {
			t.Fatal("false attribution")
		}
	}
}

type proxyMock struct {
	noOperation
	fail bool
}

func (s proxyMock) InspectClient(context.Context, sageprojection.Record, ClientRequest) (ClientResult, error) {
	if s.fail {
		return ClientResult{}, errors.New("lost observer")
	}
	return proxyControl(), nil
}
func TestProxyDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendProxyCases(&p, records)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{proxyMock{}, core.Pass}, {proxyMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestProxyRequiresActualOwnedWire(t *testing.T) {
	for _, change := range []func(*ClientResult){func(v *ClientResult) { v.Wire[0].URL = "" }, func(v *ClientResult) { v.Wire[0].URL = "https://external.example/" }, func(v *ClientResult) { v.Wire[0].Accept = "" }, func(v *ClientResult) { v.Wire[0].ContentType = "application/json" }, func(v *ClientResult) { v.Wire[0].Body = []byte(`{}`) }, func(v *ClientResult) { v.Endpoint += "?query=one" }} {
		v := proxyControl()
		change(&v)
		if judgeProxy(v, "input")[0].Verdict != core.Error {
			t.Fatal("unbound request")
		}
	}
}
