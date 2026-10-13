package sageresolution

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"net/http"
	"strings"
	"testing"
)

func wireFixture(kind string) (Result, wireScenario) {
	s := wireScenario{kind: kind, method: "GET", request: Request{NativeFunction: "resolve", Input: "did:example:a", HTTP: &core.HTTPRequest{Method: "GET", Header: http.Header{"Accept": {"application/did"}}}}}
	n := &Result{HasContent: true, ContentKind: "document", ReturnedID: s.request.Input, Metadata: json.RawMessage(`{"contentType":"application/did"}`), ContentMetadata: json.RawMessage(`{}`), Snapshot: json.RawMessage(`{"id":"did:example:a"}`), Raw: []byte(`{"id":"did:example:a"}`)}
	ex := &core.HTTPExchange{Method: "GET", TLS: true, RequestHeader: s.request.HTTP.Header.Clone(), Status: 200, Header: http.Header{"Content-Type": {"application/did"}}, Body: append([]byte(nil), n.Raw...)}
	if strings.HasPrefix(kind, "dereference") {
		s.request.NativeFunction = "dereference"
		n.ContentKind = "verification-method"
	}
	if kind == "resolve-envelope" {
		ex.Header.Set("Content-Type", checks.MediaTypeDIDResolution)
		ex.Body = []byte(`{"didDocument":{"id":"did:example:a"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{}}`)
	}
	if kind == "dereference-envelope" {
		ex.Header.Set("Content-Type", checks.MediaTypeDIDURLDereferencing)
		ex.Body = []byte(`{"content":{"id":"did:example:a"},"dereferencingMetadata":{"contentType":"application/did"},"contentMetadata":{}}`)
	}
	if kind == "deactivated" {
		n.HasContent = false
		n.Raw = nil
		n.Snapshot = nil
		n.Metadata = json.RawMessage(`{}`)
		n.ContentMetadata = json.RawMessage(`{"deactivated":true}`)
		ex.Status = 410
		ex.Header.Set("Content-Type", checks.MediaTypeDIDResolution)
		ex.Body = []byte(`{"didDocument":null,"didResolutionMetadata":{},"didDocumentMetadata":{"deactivated":true}}`)
	}
	return Result{Exchange: ex, Native: &NativeObservation{Request: Request{Function: s.request.NativeFunction, Input: s.request.Input}, Result: n}}, s
}
func TestWireBranchesRejectWrongEvidenceAndOutput(t *testing.T) {
	for _, kind := range []string{"resolve-envelope", "resolve-direct", "dereference-envelope", "dereference-direct", "deactivated"} {
		result, s := wireFixture(kind)
		for _, obs := range judgeWire(result, s, "unit") {
			if obs.Verdict != core.Pass || obs.Observed == "" {
				t.Fatal(kind, obs)
			}
		}
		for _, mutate := range []func(*Result){func(r *Result) { r.Exchange.Status = 500 }, func(r *Result) { r.Exchange.Header.Set("Content-Type", "text/plain") }, func(r *Result) { r.Exchange.Body = []byte(`{"id":"did:example:other"}`) }, func(r *Result) { r.Native.Result.HasContent = kind == "deactivated" }} {
			result, s := wireFixture(kind)
			mutate(&result)
			found := false
			for _, obs := range judgeWire(result, s, "unit") {
				found = found || obs.Verdict == core.Fail
			}
			if !found {
				t.Fatal("mutation passed", kind, result)
			}
		}
		for _, mutate := range []func(*Result){func(r *Result) { r.Exchange = nil }, func(r *Result) { r.Native = nil }, func(r *Result) { r.Native.Result = nil }, func(r *Result) { r.Native.Request.Input = "different" }, func(r *Result) { r.Native.Request.Function = "other" }, func(r *Result) { r.Native.Request.Accept = "other" }, func(r *Result) { r.Exchange.Method = "POST" }, func(r *Result) { r.Exchange.TLS = false }, func(r *Result) { r.Exchange.RequestHeader.Set("Accept", "other") }, func(r *Result) { r.Exchange.RequestBody = []byte(`{}`) }, func(r *Result) { r.Native.Result.Metadata = json.RawMessage(`null`) }, func(r *Result) { r.Native.Result.ContentMetadata = json.RawMessage(`null`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) }} {
			result, s := wireFixture(kind)
			mutate(&result)
			for _, obs := range judgeWire(result, s, "unit") {
				if obs.Verdict != core.Error || obs.Input != "unit" {
					t.Fatal(kind, obs)
				}
			}
		}
		result, s = wireFixture(kind)
		s.request.HTTP = nil
		for _, obs := range judgeWire(result, s, "unit") {
			if obs.Verdict != core.Error {
				t.Fatal(obs)
			}
		}
	}
	result, s := wireFixture("dereference-direct")
	result.Exchange.Body = []byte(`{"id":"did:example:other"}`)
	for _, obs := range judgeWire(result, s, "unit") {
		if strings.HasSuffix(obs.Statement, ".41") && obs.Verdict != core.Pass {
			t.Fatal("body corruption changed header assertion", obs)
		}
		if strings.HasSuffix(obs.Statement, ".42") && obs.Verdict != core.Fail {
			t.Fatal(obs)
		}
	}
	result, s = wireFixture("dereference-direct")
	result.Exchange.Header.Set("Content-Type", "text/plain")
	for _, obs := range judgeWire(result, s, "unit") {
		if (strings.HasSuffix(obs.Statement, ".41") || strings.HasSuffix(obs.Statement, ".42")) && obs.Verdict != core.Fail {
			t.Fatal("header corruption did not invalidate representation", obs)
		}
	}
	result, s = wireFixture("deactivated")
	result.Native.Result.ContentMetadata = json.RawMessage(`{"deactivated":false}`)
	for _, obs := range judgeWire(result, s, "unit") {
		if obs.Verdict != core.Fail {
			t.Fatal(obs)
		}
	}
}
func TestBranchProfileScopeAndMissingOperations(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendBranchCases(&p, rows)
		if err := appendWireCases(&p, rows); err != nil {
			t.Fatal(err)
		}
		if name == "did-core-1.0" && len(p.Cases) != 0 {
			t.Fatal(p.Cases)
		}
		if name == "did-1.1" && len(p.Cases) != 13 {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, subject := range []core.Subject{noOperation{}, stub{err: true}} {
				for _, obs := range c.Run(t.Context(), subject) {
					want := core.NotSupported
					if _, ok := subject.(stub); ok {
						want = core.Error
					}
					if obs.Verdict != want || obs.Input == "" {
						t.Fatal(obs)
					}
				}
			}
		}
	}
}
