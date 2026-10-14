package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func resourceControl(f resourceChoiceFixture, i int) RoutingResult {
	q := resourceChoiceRequest(f, i)
	incoming, _ := json.Marshal(map[string]any{"accept": q.Request.Accept})
	nested := map[string]any{}
	if q.Request.Accept == "application/did" {
		nested["accept"] = q.Request.Accept
	}
	if i == 0 {
		for k, v := range f.Parameters {
			nested[k] = v
		}
	}
	options, _ := json.Marshal(nested)
	media := ""
	if q.Request.Accept == "application/did" {
		media = "application/did"
	}
	driver, _ := json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": media, "NoCache": false})
	read, _ := json.Marshal(map[string]any{"Data": []byte(f.Document), "ContentType": "application/did"})
	out := RoutingResult{Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Request: q, Operation: "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference", Options: incoming, ResolveInputs: []string{"did:example:resources"}, ResolveOptions: [][]byte{options}, DriverInputs: []string{"did:example:resources"}, DriverOptions: [][]byte{driver}, DriverResults: [][]byte{read}}
	content := f.Content
	kind := f.Kind
	id := f.ID
	ct := f.Media
	if i == 1 {
		if len(f.Parameters) == 0 {
			out.Result = Result{Metadata: []byte(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`), ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
			return out
		}
		content = f.Document
		kind = "document"
		id = "did:example:resources"
		ct = "application/did"
	}
	md, _ := json.Marshal(map[string]any{"contentType": ct})
	cm := []byte(`{}`)
	if kind == "uri-list" {
		cm = []byte(`{"contentType":"text/uri-list"}`)
	}
	out.Result = Result{Metadata: md, ContentMetadata: cm, Raw: content, Snapshot: content, HasContent: true, ContentKind: kind, ReturnedID: id}
	if kind == "document" {
		out.DataModel = content
		out.Entries = []byte(`{}`)
	}
	return out
}
func resourceControls(f resourceChoiceFixture) []RoutingResult {
	return []RoutingResult{resourceControl(f, 0), resourceControl(f, 1)}
}
func TestResourceChoicePremisesAndCapability(t *testing.T) {
	fs := resourceChoiceFixtures()
	if len(fs) != 9 {
		t.Fatal(len(fs))
	}
	for _, f := range fs {
		if judgeResourceChoice(f, resourceControls(f), "unit")[0].Verdict != core.Pass {
			t.Fatal(f.Name)
		}
		if judgeResourceChoice(f, nil, "unit")[0].Verdict != core.Error {
			t.Fatal("missing")
		}
		bad := f
		bad.Name = "unknown"
		if judgeResourceChoice(bad, resourceControls(f), "unit")[0].Verdict != core.Error {
			t.Fatal("unknown")
		}
		for _, change := range []func(*RoutingResult){func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.Operation = "other" }, func(v *RoutingResult) { v.CaptureError = "lost" }, func(v *RoutingResult) { v.Request.Request.Input = "other" }, func(v *RoutingResult) { v.ResolveInputs = nil }, func(v *RoutingResult) { v.ResolveInputs[0] = "other" }, func(v *RoutingResult) { v.ResolveOptions = nil }, func(v *RoutingResult) { v.DriverInputs = nil }, func(v *RoutingResult) { v.DriverInputs[0] = "other" }, func(v *RoutingResult) { v.DriverOptions = nil }, func(v *RoutingResult) { v.DriverResults = nil }, func(v *RoutingResult) { v.Result.Native = &NativeObservation{} }, func(v *RoutingResult) { v.Result.Exchange = &core.HTTPExchange{} }, func(v *RoutingResult) { v.Options = []byte(`{`) }, func(v *RoutingResult) { v.Options = []byte(`{}`) }, func(v *RoutingResult) { v.ResolveOptions[0] = []byte(`{`) }, func(v *RoutingResult) { v.DriverOptions[0] = []byte(`{`) }, func(v *RoutingResult) { v.DriverOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{"Data":"%","ContentType":"application/did"}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{"Data":"e30=","ContentType":"application/did"}`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.ContentMetadata = []byte(`{`) }, func(v *RoutingResult) {
			v.Result.Raw = []byte(`{`)
			if v.Result.ContentKind == "document" {
				v.DataModel = []byte(`{`)
			}
		}} {
			v := resourceControls(f)
			change(&v[0])
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Error {
				t.Fatal("invalid capture accepted", f.Name)
			}
		}
		for _, change := range []func(*RoutingResult){func(v *RoutingResult) {
			v.Result.Metadata = []byte(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		}, func(v *RoutingResult) { v.Result.HasContent = false }, func(v *RoutingResult) { v.Result.ContentKind = "other" }, func(v *RoutingResult) { v.Result.ReturnedID = "other" }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{"contentType":"other"}`) }, func(v *RoutingResult) {
			v.Result.Raw = []byte(`{}`)
			if v.Result.ContentKind == "document" {
				v.DataModel = []byte(`{}`)
			}
		}} {
			v := resourceControls(f)
			change(&v[0])
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.NotSupported {
				t.Fatal("optional refusal incorrectly mandatory", f.Name)
			}
		}
		v := resourceControls(f)
		v[1].Result = Result{}
		if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Pass {
			t.Fatal("diagnostic control outcome changes MAY")
		}
		if f.Kind == "document" {
			for _, raw := range []string{"", `{`, `{}`, `[]`} {
				v := resourceControls(f)
				v[0].Result.Raw = []byte(raw)
				if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Error {
					t.Fatal("missing/mismatched actual raw archive", f.Name, raw)
				}
			}
			v := resourceControls(f)
			v[0].DataModel = []byte(`{`)
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Error {
				t.Fatal("malformed model archive")
			}
		}
		if f.Kind == "document" {
			v := resourceControls(f)
			v[0].Entries = []byte(`{"extra":1}`)
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Error {
				t.Fatal("model witness")
			}
		}
		if f.Kind == "uri-list" {
			v := resourceControls(f)
			v[0].Result.ContentMetadata = []byte(`{}`)
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.NotSupported {
				t.Fatal("media witness")
			}
		}
		if len(f.Parameters) > 0 {
			v := resourceControls(f)
			v[0].ResolveOptions[0] = []byte(`{}`)
			if judgeResourceChoice(f, v, "unit")[0].Verdict != core.Pass {
				t.Fatal("optional support coupled to separate forwarding contract")
			}
		}
	}
}

type resourceMock struct {
	noOperation
	calls, failAt int
}

func (s *resourceMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return RoutingResult{}, errors.New("lost")
	}
	for _, f := range resourceChoiceFixtures() {
		for i := range f.Requests {
			if q.Request.Input == f.Requests[i].Input && q.Request.Accept == f.Requests[i].Accept {
				return resourceControl(f, i), nil
			}
		}
	}
	return RoutingResult{}, errors.New("unknown")
}
func TestResourceChoiceDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendResourceChoiceCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendResourceChoiceCases(&p)
	if len(p.Cases) != 9 {
		t.Fatal("cases")
	}
	for _, c := range p.Cases {
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		for _, tt := range []struct {
			s core.Subject
			v core.Verdict
		}{{&resourceMock{}, core.Pass}, {&resourceMock{failAt: 1}, core.Error}, {&resourceMock{failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tt.s) {
				if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
}
