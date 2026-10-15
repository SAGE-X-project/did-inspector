package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"reflect"
	"strings"
	"testing"
)

func TestActualURLRolesAndIntegration(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/url-source-") {
			continue
		}
		count++
		obs := c.Run(t.Context(), s)
		if len(obs) != 2 {
			t.Fatal(len(obs))
		}
		for i, o := range obs {
			want := core.Fail
			if i == 1 {
				want = core.Pass
			}
			if o.Verdict != want {
				var evidence struct {
					Error     string                           `json:"analysis_error"`
					Handler   []sageresolution.RoutingResult   `json:"handler"`
					Retrieval []sageresolution.RetrievalResult `json:"retrieval"`
				}
				_ = json.Unmarshal([]byte(o.Observed), &evidence)
				t.Log("evidence error", evidence.Error)
				for _, h := range evidence.Handler {
					t.Log(h.Request.Request.Input, h.ResourceHandler, string(h.Result.Metadata))
				}
				for _, r := range evidence.Retrieval {
					t.Log(r.Reference, r.ParsedURL, len(r.Calls), r.Error, string(r.Method))
				}
				t.Fatal(o.Statement, o.Verdict)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
func TestURLPartsAndPassiveHandlerBoundaries(t *testing.T) {
	u, e := did.ParseURL("did:example:resources/path?relativeRef=next#part?piece")
	if e != nil {
		t.Fatal(e)
	}
	v := urlParts(u)
	if v.Input != u.String() || v.Primary != "did:example:resources/path?relativeRef=next" || v.Fragment != "part?piece" || !v.HasFragment || !v.HasQuery || v.Path != "/path" || v.Query != "relativeRef=next" {
		t.Fatal(v)
	}
	out := sageresolution.RoutingResult{CaptureError: "previous"}
	result, handled := observeResourceHandler(&out)(t.Context(), u, resolution.Result{}, resolution.DereferenceOptions{})
	if handled || !reflect.DeepEqual(result, resolution.DereferenceResult{}) || out.CaptureError != "previous" || len(out.ResourceHandler) != 1 || out.ResourceHandler[0].URL != v || len(out.ResourceHandler[0].Model) != 0 {
		t.Fatal(out)
	}
	doc, _, err := consumer.New().Consume([]byte(`{"id":"did:example:resources"}`), "application/did", representation.ConsumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out = sageresolution.RoutingResult{}
	_, handled = observeResourceHandler(&out)(t.Context(), u, resolution.Result{Document: doc, ResolutionMetadata: resolution.ResolutionMetadata{Extra: map[string]any{"bad": func() {}}}}, resolution.DereferenceOptions{Extra: map[string]any{"bad": func() {}}})
	if handled || out.CaptureError == "" || out.ResourceHandler[0].CaptureError == "" || len(out.ResourceHandler[0].Model) == 0 {
		t.Fatal(out)
	}
	s, _ := identify(pinned)
	q := sageresolution.RoutingRequest{Document: sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:example:resources"}`), MediaType: "application/did"}, Request: sageresolution.Request{Function: "resolve", Input: "did:example:resources"}, ObserveResourceHandler: true}
	if _, e := s.InspectRouting(t.Context(), q); e == nil {
		t.Fatal("observer on non-dereference")
	}
}
