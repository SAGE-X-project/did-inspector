package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"strings"
)

//go:embed routing_cases.json
var routingBytes []byte

type routingFixture struct {
	Name       string          `json:"name"`
	Request    Request         `json:"request"`
	Document   json.RawMessage `json:"document"`
	Statements []string        `json:"statements"`
	Content    json.RawMessage `json:"expected_content"`
	ErrorType  string          `json:"error_type"`
	Forwarded  map[string]any  `json:"forwarded_options"`
}

func routingFixtures() []routingFixture {
	var out []routingFixture
	_ = json.Unmarshal(routingBytes, &out)
	return out
}
func routingRequest(f routingFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request}
}
func judgeRouting(f routingFixture, out RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable(f.Statements, core.Error, "Actual pinned root resolver/dereferencer library selected by SAGE, independently configured with a literal did:example driver. The fixture is not a SAGE registry, authoritative source, actual history or deployed service. Supplied options and actual nested Resolve and Read calls are retained unchanged. Independent fixed selected-service, RFC3986 relative-reference, endpoint-list, fragment and no-handler error expectations only. Internal initialization/arithmetic/iteration steps are not inferred from final output.", input, out)
	known := false
	for _, candidate := range routingFixtures() {
		a, _ := json.Marshal(candidate)
		b, _ := json.Marshal(f)
		if bytes.Equal(a, b) {
			known = true
		}
	}
	q := routingRequest(f)
	if !known || out.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || out.CaptureError != "" || out.Operation != "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference" || !reflect.DeepEqual(out.Request, q) || out.Request.Request.Function != q.Request.Function || out.Request.Request.Input != q.Request.Input || out.Request.Request.Accept != q.Request.Accept || !bytes.Equal(out.Request.Document.Data, q.Document.Data) || out.Request.Document.MediaType != q.Document.MediaType || len(out.ResolveInputs) != 1 || out.ResolveInputs[0] != "did:example:123" || len(out.ResolveOptions) != 1 {
		return obs
	}
	incoming, e := core.ParseJSON(out.Options)
	if e != nil {
		return obs
	}
	expected := core.Object()
	if q.Request.Accept != "" {
		expected = core.Object(core.M("accept", core.String(q.Request.Accept)))
	}
	if q.Request.Relationship != "" {
		expected.Object = append(expected.Object, core.M("verificationRelationship", core.String(q.Request.Relationship)))
	}
	if !equalObserved(incoming, expected, "metadata") {
		return obs
	}
	if len(f.Statements) == 1 && strings.HasSuffix(f.Statements[0], "dereferencing-algorithm-resource.5") {
		options, e := core.ParseJSON(out.ResolveOptions[0])
		b, _ := json.Marshal(f.Forwarded)
		want, _ := core.ParseJSON(b)
		if e != nil {
			return obs
		}
		obs[0].Verdict = core.Pass
		if !equalObserved(options, want, "metadata") {
			obs[0].Verdict = core.Fail
			obs[0].Detail += " Actual nested Resolve omits accept=text/uri-list; the pinned all-options MUST has no exception. Return processing and correction choices are judged separately."
		}
		obs[0].Expected = "All original dereferencing options and DID parameters appear in the actual nested Resolve input"
		return obs
	}
	if len(out.DriverOptions) != 1 {
		return obs
	}
	driver, e := parse(out.DriverOptions[0])
	if e != nil {
		return obs
	}
	expectedMedia := ""
	if q.Request.Accept == "application/did" {
		expectedMedia = "application/did"
	}
	wantDriver := core.Object(core.M("VersionID", core.String("")), core.M("VersionTime", core.Null()), core.M("MediaType", core.String(expectedMedia)), core.M("NoCache", core.Bool(false)))
	if !equalObserved(driver.Value(), wantDriver, "metadata") {
		return obs
	}
	result := out.Result
	md, e := parse(result.Metadata)
	cm, ee := parse(result.ContentMetadata)
	if e != nil || ee != nil || result.Native != nil || result.Exchange != nil {
		return obs
	}
	expectedContent, e := core.ParseJSON(f.Content)
	if e != nil {
		return obs
	}
	actual := result.Raw
	if result.ContentKind == "document" {
		actual = out.DataModel
		entries, err := parse(out.Entries)
		if err != nil || entries.Len() != 0 {
			return obs
		}
	}
	value, ee := core.ParseJSON(actual)
	if ee != nil {
		return obs
	}

	if (result.HasContent && value.Kind == core.KindNull) || (!result.HasContent && value.Kind != core.KindNull) {
		return obs
	}
	_, errorPresent := md.Get("error")
	descriptor := nativeErrorDescriptor(md)
	errorValue, _ := md.Get("error")
	typ, _ := errorValue.Get("type")
	errorMatch := descriptor && (f.ErrorType == "ANY" || typ.Str == "https://www.w3.org/ns/did#"+f.ErrorType)
	nullContent := !result.HasContent && value.Kind == core.KindNull
	kind := "document"
	if expectedContent.Kind == core.KindArray {
		kind = "set"
	}
	contentMatch := result.HasContent && equalObserved(value, expectedContent, kind)
	ct, _ := md.Get("contentType")
	resolutionMetadata := !errorPresent && ct.Kind == core.KindString && ct.Str == q.Request.Accept
	contentMetadata := cm.Len() == 0
	if expectedContent.Kind == core.KindArray {
		ct, _ := cm.Get("contentType")
		contentMetadata = ct.Kind == core.KindString && ct.Str == "text/uri-list"
	}
	whole := contentMatch && resolutionMetadata && contentMetadata
	if f.ErrorType != "" {
		whole = errorMatch && nullContent && cm.Len() == 0
	}
	for i := range obs {
		pass := whole
		id := obs[i].Statement
		switch id {
		case "res10-crd20261001#dereferencing-algorithm-resource.41", "res10-crd20261001#dereferencing-algorithm-resource.50":
			pass = errorMatch
		case "res10-crd20261001#dereferencing-algorithm-resource.42", "res10-crd20261001#dereferencing-algorithm-resource.51":
			pass = nullContent
		case "res10-crd20261001#dereferencing-algorithm-resource.43", "res10-crd20261001#dereferencing-algorithm-resource.52":
			pass = cm.Len() == 0
		case "res10-crd20261001#dereferencing-algorithm-fragment.8", "res10-crd20261001#dereferencing-algorithm-fragment.4":
			if f.ErrorType != "" {
				pass = descriptor
			} else {
				pass = contentMatch
			}
		case "res10-crd20261001#dereferencing-algorithm-resource.32", "res10-crd20261001#dereferencing-algorithm-resource.37":
			pass = md.Value().Kind == core.KindObject && !errorPresent
		case "res10-crd20261001#dereferencing-algorithm-resource.34":
			pass = cm.Len() == 0
		case "res10-crd20261001#dereferencing-algorithm-resource.39":
			pass = contentMetadata
		case "res10-crd20261001#dereferencing-algorithm-resource.18", "res10-crd20261001#dereferencing-algorithm-resource.19", "res10-crd20261001#dereferencing-algorithm-resource.30":
			pass = routingServiceIDs(value, expectedContent)
		case "res10-crd20261001#dereferencing-algorithm-resource.22", "res10-crd20261001#dereferencing-algorithm-resource.23", "res10-crd20261001#dereferencing-algorithm-resource.24", "res10-crd20261001#dereferencing-algorithm-resource.25", "res10-crd20261001#dereferencing-algorithm-resource.28", "res10-crd20261001#dereferencing-algorithm-resource.33", "res10-crd20261001#dereferencing-algorithm-resource.38", "res10-crd20261001#dereferencing-algorithm-fragment.9", "res10-crd20261001#dereferencing-algorithm-fragment.10":
			pass = contentMatch
		}
		obs[i].Verdict = core.Fail
		if pass {
			obs[i].Verdict = core.Pass
		}
		obs[i].Expected = "Independent selected-service/content/metadata/error member or complete tuple matches the pinned clause; other members have separate verdicts"
	}
	return obs
}
func appendRoutingCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range routingFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/remaining-routing-%s", p.Name, f.Name), Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(RoutingSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no root routing library observer", string(input), nil)
			}
			out, e := s.InspectRouting(ctx, routingRequest(f))
			if e != nil {
				return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
			}
			return judgeRouting(f, out, string(input))
		}})
	}
}

func routingServiceIDs(actual, expected core.Value) bool {
	a, ap := actual.Get("service")
	b, bp := expected.Get("service")
	if !ap || !bp || a.Kind != core.KindArray || b.Kind != core.KindArray {
		return false
	}
	left, right := []core.Value{}, []core.Value{}
	for _, v := range a.Array {
		id, ok := v.Get("id")
		if !ok || id.Kind != core.KindString {
			return false
		}
		left = append(left, id)
	}
	for _, v := range b.Array {
		id, ok := v.Get("id")
		if !ok || id.Kind != core.KindString {
			return false
		}
		right = append(right, id)
	}
	return equalObserved(core.Array(left...), core.Array(right...), "set")
}
