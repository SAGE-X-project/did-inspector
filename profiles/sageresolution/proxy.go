package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"net"
	"net/url"
	"reflect"
)

const proxyReply = `{"didDocument":{"id":"did:sage:web:registry.example:agent-1"},"didResolutionMetadata":{"contentType":"application/did","proof":[{"type":"ExampleStructuralProof","publicFixture":"upstream-metadata-only"}],"extension":{"source":"literal owned upstream"}},"didDocumentMetadata":{"created":"2030-01-02T03:04:05Z","updated":"2030-01-02T03:04:05Z","versionId":"7","deactivated":false,"proof":[{"type":"ExampleStructuralProof","publicFixture":"upstream-document-only"}],"extension":{"source":"literal owned upstream"}}}`

func proxyRequest() ClientRequest {
	return ClientRequest{Request: Request{Function: "resolve", Input: policyDID, Accept: "application/did"}, Reply: []byte(proxyReply)}
}
func judgeProxy(v ClientResult, input string) []core.Observation {
	id := "res10-crd20261001#resolver-architectures-proxied.2"
	obs := libraryUnavailable([]string{id}, core.Error, "Actual selected universal Client acting as a downstream resolver against an explicitly controlled owned upstream response fixture. All supplied resolution and document metadata, including structural proof maps and extension maps, are compared independently. The fixture is not a SAGE server response or verifiable registry, proof signatures/authority and real deployment are unestablished.", input, v)
	if !reflect.DeepEqual(v.Request, proxyRequest()) || v.Operation != "github.com/sage-x-project/did-go/resolution/universal.Client.resolve" || v.ServerRole != "controlled client response fixture; not SAGE server output" || !v.ServerTLS || v.ServerCalls != 1 || len(v.Wire) != 1 || len(v.Native) != 0 || len(v.Consumer) != 1 {
		return obs
	}
	u, e := url.Parse(v.Endpoint)
	if e != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		return obs
	}
	if u.Path != "/1.0/identifiers/" || u.RawQuery != "" || u.User != nil || u.Fragment != "" || v.Wire[0].URL != v.Endpoint+policyDID || v.Wire[0].Accept != "application/did" || v.Wire[0].ContentType != "" || len(v.Wire[0].Body) != 0 || v.Wire[0].CaptureError != "" || v.Wire[0].Method != "GET" || v.Consumer[0].CaptureError != "" || v.Consumer[0].Error != "" || !v.Result.HasContent || v.Result.ReturnedID != policyDID {
		return obs
	}
	reply, _ := parse([]byte(proxyReply))
	wantMD, _ := reply.Get("didResolutionMetadata")
	wantDM, _ := reply.Get("didDocumentMetadata")
	md, e := parse(v.Result.Metadata)
	dm, e2 := parse(v.Result.ContentMetadata)
	if e != nil || e2 != nil {
		return obs
	}
	obs[0].Verdict = core.Fail
	if equalObserved(md.Value(), wantMD, "metadata") && equalObserved(dm.Value(), wantDM, "metadata") {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Exact transparent preservation of both independent upstream metadata maps and structural proofs"
	return obs
}
func appendProxyCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	r := records[0]
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-proxy-metadata", Profile: p.Name, Statements: []string{"res10-crd20261001#resolver-architectures-proxied.2"}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := proxyRequest()
		input, _ := json.Marshal(struct {
			Record  sageprojection.Record
			Request ClientRequest
		}{r, q})
		s, ok := target.(ClientSubject)
		if !ok {
			return libraryUnavailable([]string{"res10-crd20261001#resolver-architectures-proxied.2"}, core.NotSupported, "no actual downstream Client", string(input), nil)
		}
		out, e := s.InspectClient(ctx, r, q)
		if e != nil {
			return libraryUnavailable([]string{"res10-crd20261001#resolver-architectures-proxied.2"}, core.Error, e.Error(), string(input), out)
		}
		return judgeProxy(out, string(input))
	}})
}
