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

const resolverProofID = "res10-crd20261001#resolver-architectures.3"
const proofReply = `{"didDocument":{"id":"did:sage:web:registry.example:agent-1"},"didResolutionMetadata":{"contentType":"application/did","proof":[{"type":"ExampleStructuralProof","publicFixture":"optional-return-only"}]},"didDocumentMetadata":{}}`
const proofAbsentReply = `{"didDocument":{"id":"did:sage:web:registry.example:agent-1"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{}}`

func resolverProofRequests() []ClientRequest {
	out := []ClientRequest{}
	for _, reply := range []string{proofReply, proofAbsentReply} {
		out = append(out, ClientRequest{Request: Request{Function: "resolve", Input: policyDID, Accept: "application/did"}, Reply: []byte(reply)})
	}
	return out
}
func judgeResolverProof(values []ClientResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{resolverProofID}, core.Error, "Actual selected universal Client.Resolve returns an optional proof from a literal owned TLS upstream, with proof-absent control. This is a selected downstream resolver capability, not SAGE method proof generation, signature validity, trust, operational authority or correctness verification. Refusal/loss is NOT_SUPPORTED for this MAY, not a mandatory failure.", input, values)
	qs := resolverProofRequests()
	if len(values) != len(qs) {
		return obs
	}
	for i, v := range values {
		u, e := url.Parse(v.Endpoint)
		if e != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" || u.Path != "/1.0/identifiers/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return obs
		}
		if !reflect.DeepEqual(v.Request, qs[i]) || v.Operation != "github.com/sage-x-project/did-go/resolution/universal.Client.resolve" || v.ServerRole != "controlled client response fixture; not SAGE server output" || !v.ServerTLS || v.ServerCalls != 1 || len(v.Wire) != 1 || len(v.Native) != 0 || len(v.Consumer) != 1 {
			return obs
		}
		w := v.Wire[0]
		c := v.Consumer[0]
		if w.CaptureError != "" || w.Method != "GET" || w.URL != v.Endpoint+policyDID || w.Accept != "application/did" || w.ContentType != "" || len(w.Body) != 0 || c.Operation != pipelineConsumer || c.MediaType != "application/did" || !optionJSONEqual(c.Input, `{"id":"did:sage:web:registry.example:agent-1"}`) || c.Require != "unknown" || c.Expected != "unknown" || c.Strict {
			return obs
		}
		if v.Consumer[0].Error != "" {
			obs[0].Verdict = core.NotSupported
			return obs
		}
		if v.Consumer[0].CaptureError != "" {
			return obs
		}
		if !v.Result.HasContent || v.Result.ReturnedID != policyDID {
			obs[0].Verdict = core.NotSupported
			return obs
		}
		md, e := parse(v.Result.Metadata)
		if e != nil || md.Value().Kind != core.KindObject {
			return obs
		}
		proof, present := md.Get("proof")
		if i == 0 {
			expected, _ := parse([]byte(proofReply))
			expectedMD, _ := expected.Get("didResolutionMetadata")
			expectedProof, _ := expectedMD.Get("proof")
			if !present || !equalObserved(proof, expectedProof, "metadata") {
				obs[0].Verdict = core.NotSupported
				return obs
			}
		}
		// The absent control remains diagnostic. MAY permits a resolver to add its
		// own proof; an unexpected proof here does not violate the selected clause.
	}
	obs[0].Verdict = core.Pass
	obs[0].Expected = "Actual downstream resolution result includes the exact selected public proof-shaped map; no cryptographic proof assertion"
	return obs
}
func appendResolverProofCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/representation-options-resolver-proof", Profile: p.Name, Statements: []string{resolverProofID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		qs := resolverProofRequests()
		input, _ := json.Marshal(qs)
		s, ok := target.(ClientSubject)
		if !ok {
			return libraryUnavailable([]string{resolverProofID}, core.NotSupported, "no actual downstream resolver observer", string(input), nil)
		}
		values := []ClientResult{}
		for _, q := range qs {
			v, e := s.InspectClient(ctx, records[0], q)
			values = append(values, v)
			if e != nil {
				return libraryUnavailable([]string{resolverProofID}, core.Error, e.Error(), string(input), values)
			}
		}
		return judgeResolverProof(values, string(input))
	}})
}
