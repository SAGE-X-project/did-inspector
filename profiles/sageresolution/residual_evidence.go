package sageresolution

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"reflect"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const residualHistory = "history-metadata"
const residualProxy = "proxy-metadata"
const residualDocument = `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:sage:web:registry.example:agent-1"}`
const residualModel = `{"id":"did:sage:web:registry.example:agent-1"}`

func residualIDs(kind string) []string {
	if kind == residualHistory {
		return []string{"res10-crd20261001#did-document-metadata.8", "res10-crd20261001#did-document-metadata.12"}
	}
	return []string{"res10-crd20261001#resolver-architectures-proxied.3"}
}
func residualRequests(kind string) []ClientRequest {
	out := []ClientRequest{}
	if kind == residualHistory {
		for i, version := range []string{"7", "8", "7"} {
			md := map[string]any{"versionId": version}
			if i == 0 {
				md["nextVersionId"] = "8"
				md["nextUpdate"] = "2030-01-02T03:04:05Z"
			}
			reply, _ := json.Marshal(map[string]any{"didDocument": json.RawMessage(residualDocument), "didResolutionMetadata": map[string]any{"contentType": "application/did"}, "didDocumentMetadata": md})
			out = append(out, ClientRequest{Request: Request{Function: "resolve", Input: policyDID, Accept: "application/did", Options: map[string]any{"versionId": version}}, Reply: reply})
		}
	} else {
		for _, md := range []string{`{}`, `{"contentType":"application/did"}`} {
			reply := `{"didDocument":` + residualDocument + `,"didResolutionMetadata":` + md + `,"didDocumentMetadata":{}}`
			out = append(out, ClientRequest{Request: Request{Function: "resolve", Input: policyDID, Accept: "application/did"}, Reply: []byte(reply)})
		}
	}
	return out
}
func judgeResidual(kind string, values []ClientResult, input string) []core.Observation {
	detail := "Actual original universal Client.Resolve, controlled public upstream reply and owned loopback TLS. Selected downstream capability only; no registry history, authority, Update execution, signature validity or complete proxy-preservation claim. Optional absence controls are diagnostic; refusal/loss is NOT_SUPPORTED for this MAY."
	obs := libraryUnavailable(residualIDs(kind), core.Error, detail, input, values)
	set := func(v core.Verdict) []core.Observation {
		for i := range obs {
			obs[i].Verdict = v
		}
		return obs
	}
	qs := residualRequests(kind)
	if len(values) != len(qs) {
		return obs
	}
	for i, v := range values {
		u, e := url.Parse(v.Endpoint)
		if e != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" || u.Path != "/1.0/identifiers/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
			return obs
		}
		if !reflect.DeepEqual(v.Request, qs[i]) || v.Operation != "github.com/sage-x-project/did-go/resolution/universal.Client.resolve" || v.ServerRole != "controlled client response fixture; not SAGE server output" || !v.ServerTLS || v.ServerCalls != 1 || len(v.Wire) != 1 || len(v.Native) != 0 || len(v.Consumer) != 1 {
			return obs
		}
		expectedURL := v.Endpoint + policyDID
		if kind == residualHistory {
			expectedURL = v.Endpoint + percentIdentifier(policyDID) + "?versionId=" + qs[i].Request.Options["versionId"].(string)
		}
		w, c := v.Wire[0], v.Consumer[0]
		media := "application/did"
		if kind == residualProxy && i == 0 {
			media = "application/json"
		}
		if w.CaptureError != "" || w.Method != "GET" || w.URL != expectedURL || w.Accept != "application/did" || w.ContentType != "" || len(w.Body) != 0 || c.Operation != pipelineConsumer || c.MediaType != media || !optionJSONEqual(c.Input, residualDocument) || c.Require != "unknown" || c.Expected != "unknown" || c.Strict {
			return obs
		}
		if c.CaptureError != "" {
			return obs
		}
		if c.Error != "" {
			return set(core.NotSupported)
		}
		if c.Version != "1.1" || !c.JSONLD || !optionJSONEqual(c.Model, residualModel) || !optionJSONEqual(c.Entries, `{"@context":"https://www.w3.org/ns/did/v1.1"}`) || !v.Result.HasContent || v.Result.ReturnedID != policyDID {
			return set(core.NotSupported)
		}
		md, e := parse(v.Result.Metadata)
		if e != nil || md.Value().Kind != core.KindObject {
			return obs
		}
		if _, present := md.Get("error"); present {
			return set(core.NotSupported)
		}
		dm, e := parse(v.Result.ContentMetadata)
		if e != nil || dm.Value().Kind != core.KindObject {
			return obs
		}
		if kind == residualHistory {
			version, ok := dm.Get("versionId")
			if !ok || version.Kind != core.KindString || version.Str != qs[i].Request.Options["versionId"] {
				return set(core.NotSupported)
			}
			if i == 0 {
				next, ok := dm.Get("nextVersionId")
				date, present := dm.Get("nextUpdate")
				if !present || date.Kind != core.KindString || date.Str != "2030-01-02T03:04:05Z" {
					obs[0].Verdict = core.NotSupported
				}
				if !ok || next.Kind != core.KindString || next.Str != "8" {
					obs[1].Verdict = core.NotSupported
				}
			}
			// MAY does not require absence for a latest or omitted-field control.
		} else {
			ct, ok := md.Get("contentType")
			if !ok || ct.Kind != core.KindString || ct.Str != "application/did" {
				return set(core.NotSupported)
			}
		}
	}
	for i := range obs {
		if obs[i].Verdict == core.Error {
			obs[i].Verdict = core.Pass
		}
	}
	return obs
}
func appendResidualCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for _, kind := range []string{residualHistory, residualProxy} {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/residual-" + kind, Profile: p.Name, Statements: residualIDs(kind), Run: func(ctx context.Context, target core.Subject) []core.Observation {
			qs := residualRequests(kind)
			input, _ := json.Marshal(qs)
			s, ok := target.(ClientSubject)
			if !ok {
				return libraryUnavailable(residualIDs(kind), core.NotSupported, "no actual downstream Client observer", string(input), nil)
			}
			values := []ClientResult{}
			for _, q := range qs {
				v, e := s.InspectClient(ctx, records[0], q)
				values = append(values, v)
				if e != nil {
					return libraryUnavailable(residualIDs(kind), core.Error, e.Error(), string(input), values)
				}
			}
			return judgeResidual(kind, values, string(input))
		}})
	}
}
