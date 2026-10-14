package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"net/http"
	"net/http/httptest"
	"testing"
)

func trustControl(t *testing.T) []TrustResult {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	cert := append([]byte(nil), srv.Certificate().Raw...)
	role := "actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim"
	good := TrustResult{Role: role, Endpoint: srv.URL + "/1.0/identifiers/", ClientResult: nativeRemainingKeyControl(), HTTPCalls: 1, ClientVerified: true, ServerVerified: true, TLSVersion: 0x0304, ClientCertificate: cert, ServerCertificate: cert, ClientPeer: cert, ServerPeer: cert}
	bad := good
	bad.ClientMissing = true
	bad.HTTPCalls = 0
	bad.ClientVerified = false
	bad.ClientPeer = nil
	bad.ClientResult = Result{Metadata: []byte(`{"error":{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}}`), ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
	return []TrustResult{good, bad}
}
func TestTrustObservationGuards(t *testing.T) {
	values := trustControl(t)
	for _, o := range judgeTrust(values, "input") {
		if o.Verdict != core.Pass {
			t.Fatal(o.Verdict)
		}
	}
	for _, change := range []func(*TrustResult){func(r *TrustResult) { r.Endpoint = "https://external.example/1.0/identifiers/" }, func(r *TrustResult) { r.Endpoint = "http://127.0.0.1:123/1.0/identifiers/" }, func(r *TrustResult) { r.Role = "operational trust" }, func(r *TrustResult) { r.CaptureError = "lost" }, func(r *TrustResult) { r.ClientCertificate = nil }, func(r *TrustResult) { r.ServerCertificate = nil }, func(r *TrustResult) { r.ServerVerified = false }, func(r *TrustResult) { r.ClientVerified = false }, func(r *TrustResult) { r.ClientPeer = nil }, func(r *TrustResult) { r.ServerPeer = nil }, func(r *TrustResult) { r.TLSVersion = 0x0300 }, func(r *TrustResult) { r.HTTPCalls = 0 }, func(r *TrustResult) { r.ClientMissing = true }} {
		v := trustControl(t)
		change(&v[0])
		for _, o := range judgeTrust(v, "input") {
			if o.Statement == "res10-crd20261001#resolver-architectures.2" && o.Verdict == core.Pass {
				t.Fatal("false trusted client PASS")
			}
		}
	}
	for _, change := range []func(*TrustResult){func(r *TrustResult) { r.ClientMissing = false }, func(r *TrustResult) { r.HTTPCalls = 1 }, func(r *TrustResult) { r.ClientResult.HasContent = true }, func(r *TrustResult) { r.ClientResult.Metadata = []byte(`{"error":null}`) }} {
		v := trustControl(t)
		change(&v[1])
		if judgeTrust(v, "input")[1].Verdict == core.Pass {
			t.Fatal("missing identity falsely authenticated")
		}
	}
	if judgeTrust(nil, "input")[0].Verdict != core.Error {
		t.Fatal("partial evidence")
	}
}

type trustMock struct {
	noOperation
	values []TrustResult
	failAt int
	calls  int
}

func (s *trustMock) InspectTrust(_ context.Context, _ sageprojection.Record, _ bool) (TrustResult, error) {
	i := s.calls
	s.calls++
	out := s.values[i]
	if s.calls == s.failAt {
		return out, errors.New("adapter failed")
	}
	return out, nil
}
func TestTrustDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendTrustCases(&p, records)
		want := 1
		if name != "did-1.1" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{&trustMock{values: trustControl(t)}, core.Pass}, {&trustMock{values: trustControl(t), failAt: 1}, core.Error}, {&trustMock{values: trustControl(t), failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o.Verdict)
					}
				}
			}
		}
	}
}

func TestTrustVerdictsRemainIndependent(t *testing.T) {
	v := trustControl(t)
	v[0].ClientVerified = false
	o := judgeTrust(v, "input")
	if o[0].Verdict != core.Pass || o[1].Verdict != core.Fail {
		t.Fatal(o)
	}
	v = trustControl(t)
	v[0].ClientResult = Result{Metadata: []byte(`{"error":null}`)}
	for _, o := range judgeTrust(v, "input") {
		if o.Verdict != core.Pass {
			t.Fatal("application output cannot undo observed TLS", o)
		}
	}
}
