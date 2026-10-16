package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

const applicationDID = "did:example:resources"
const applicationURL = applicationDID + "/public-resource"
const applicationDocument = `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:resources"}`
const applicationModel = `{"id":"did:example:resources"}`
const applicationEntries = `{"@context":"https://www.w3.org/ns/did/v1.1"}`
const applicationResource = `{"id":"did:example:resources/public-resource","label":"public application resource"}`

func applicationRequests() []RoutingRequest {
	out := []RoutingRequest{}
	for i, mode := range []string{"handled", "unhandled", "", "handled"} {
		input := applicationURL
		if i == 3 {
			input = applicationDID
		}
		out = append(out, RoutingRequest{ApplicationHandler: mode, Document: ConsumptionRequest{Data: []byte(applicationDocument), MediaType: "application/did"}, Request: Request{Function: "dereference", Input: input}})
	}
	return out
}
func applicationWitness(q RoutingRequest, v RoutingResult) bool {
	if !reflect.DeepEqual(q, v.Request) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != IntegerSourceModule+"/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != applicationDID || len(v.DriverInputs) != 1 || v.DriverInputs[0] != applicationDID || len(v.ResolveOptions) != 1 || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || len(v.Consumption) != 1 || len(v.Production) != 0 || len(v.ResourceHandler) != 0 || v.Result.Native != nil || v.Result.Exchange != nil {
		return false
	}
	if !optionJSONEqual(v.Options, `{}`) || !optionJSONEqual(v.ResolveOptions[0], `{}`) || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"","NoCache":false}`) {
		return false
	}
	var read struct {
		ContentType string
		Data        []byte
	}
	if json.Unmarshal(v.DriverResults[0], &read) != nil || read.ContentType != "application/did" || !optionJSONEqual(read.Data, applicationDocument) {
		return false
	}
	c := v.Consumption[0]
	return c.Operation == pipelineConsumer && c.Error == "" && c.CaptureError == "" && c.MediaType == "application/did" && c.Require == "unknown" && c.Expected == "unknown" && !c.Strict && c.Version == "1.1" && c.JSONLD && optionJSONEqual(c.Input, applicationDocument) && optionJSONEqual(c.Model, applicationModel) && optionJSONEqual(c.Entries, applicationEntries) && optionJSONEqual(v.DataModel, applicationModel) && optionJSONEqual(v.ResolvedDataModel, applicationModel) && optionJSONEqual(v.Entries, applicationEntries) && optionJSONEqual(v.ResolvedEntries, applicationEntries) && optionJSONEqual(v.ResolvedMetadata, `{"contentType":"application/did"}`)
}
func judgeApplication(values []RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{applicationID}, core.Error, "Actual original dereferencer dispatch to an explicitly supplied controlled application callback. Positive handled, unhandled, absent configuration and no-path controls retain actual nested resolution, callback input/return and final content separately. This is a selected extension-point capability, not SAGE method path support, authority, external retrieval, arbitrary application correctness or full dereferencing conformance. Control fallback is diagnostic, not an additional MAY obligation.", input, values)
	qs := applicationRequests()
	if len(values) != len(qs) {
		return obs
	}
	for i, v := range values {
		if !applicationWitness(qs[i], v) {
			return obs
		}
		calls := 0
		if i < 2 {
			calls = 1
		}
		if len(v.ApplicationHandler) != calls {
			return obs
		}
		md, e := parse(v.Result.Metadata)
		if e != nil || md.Value().Kind != core.KindObject {
			return obs
		}
		cm, e := parse(v.Result.ContentMetadata)
		if e != nil || cm.Value().Kind != core.KindObject {
			return obs
		}
		if calls == 1 {
			h := v.ApplicationHandler[0]
			wanted := URLParts{Input: applicationURL, Primary: applicationURL, Path: "/public-resource"}
			if h.Input.Operation != IntegerSourceModule+"/dereferencer.ResourceHandler" || h.Input.Role != "explicit controlled application callback; not SAGE method support" || h.Input.URL != wanted || h.Input.CaptureError != "" || !optionJSONEqual(h.Input.Options, `{}`) || !optionJSONEqual(h.Input.Model, applicationModel) || !optionJSONEqual(h.Input.Entries, applicationEntries) || !optionJSONEqual(h.Input.Metadata, `{"contentType":"application/did"}`) || h.Handled != (i == 0) {
				return obs
			}
			if i == 0 {
				// Both literal oracle and same-call equality are required, so an invented
				// callback result cannot be reused as its own final-output oracle.
				for _, r := range []Result{h.Returned, v.Result} {
					if !r.HasContent || r.ContentKind != "map" || r.ReturnedID != applicationURL || !optionJSONEqual(r.Raw, applicationResource) || !optionJSONEqual(r.Snapshot, applicationResource) || !optionJSONEqual(r.Metadata, `{"contentType":"application/json"}`) || !optionJSONEqual(r.ContentMetadata, `{"versionId":"application-1"}`) || r.Native != nil || r.Exchange != nil {
						return obs
					}
				}
			} else if h.Returned.HasContent || !optionJSONEqual(h.Returned.Raw, `null`) || !optionJSONEqual(h.Returned.Metadata, `{}`) || !optionJSONEqual(h.Returned.ContentMetadata, `{}`) {
				return obs
			}
		}
		if i == 0 {
			continue
		}
		// These controls establish original dispatch/fallback provenance. Their
		// outcomes are not used as a normative FAIL of this optional feature.
		if i < 3 {
			errorValue, ok := md.Get("error")
			if !ok || errorValue.Kind != core.KindObject || v.Result.HasContent || !optionJSONEqual(v.Result.Raw, `null`) {
				return obs
			}
			typ, ok := errorValue.Get("type")
			if !ok || typ.Kind != core.KindString || typ.Str != "https://www.w3.org/ns/did#NOT_FOUND" {
				return obs
			}
		} else if !v.Result.HasContent || v.Result.ContentKind != "document" || v.Result.ReturnedID != applicationDID || !optionJSONEqual(v.Result.Metadata, `{"contentType":"application/did"}`) {
			return obs
		}
	}
	obs[0].Verdict = core.Pass
	return obs
}
func appendApplicationCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/extension-application-handler", Profile: p.Name, Statements: []string{applicationID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		qs := applicationRequests()
		input, _ := json.Marshal(qs)
		s, ok := target.(RoutingSubject)
		if !ok {
			return libraryUnavailable([]string{applicationID}, core.Error, "missing selected application dispatcher observer", string(input), nil)
		}
		values := []RoutingResult{}
		for _, q := range qs {
			v, e := s.InspectRouting(ctx, q)
			values = append(values, v)
			if e != nil {
				return libraryUnavailable([]string{applicationID}, core.Error, e.Error(), string(input), values)
			}
		}
		return judgeApplication(values, string(input))
	}})
}
