package sage

import (
	"testing"
	"time"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func typedRequestForTest() sageresolution.TypedProductionRequest {
	return sageresolution.TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, Fields: []sageresolution.TypedMember{
		{Name: "text", Value: sageresolution.TypedValue{Kind: "string", Text: "한글\n"}},
		{Name: "integer", Value: sageresolution.TypedValue{Kind: "integer", Text: "42"}},
		{Name: "double", Value: sageresolution.TypedValue{Kind: "double", Text: "2"}},
		{Name: "clock", Value: sageresolution.TypedValue{Kind: "datetime", Text: "2020-12-21T04:17:47.123456789+09:00"}},
		{Name: "list", Value: sageresolution.TypedValue{Kind: "list", Items: []sageresolution.TypedValue{{Kind: "boolean", Flag: true}, {Kind: "null"}, {Kind: "map", Members: []sageresolution.TypedMember{{Name: "nested", Value: sageresolution.TypedValue{Kind: "double", Text: "1.5"}}}}}}},
	}, Entries: []sageresolution.TypedMember{{Name: "representationNote", Value: sageresolution.TypedValue{Kind: "string", Text: "kept"}}}}
}
func TestTypedProducerUsesActualTypesAndPreservesPreInput(t *testing.T) {
	s, _ := identify(pinned)
	for _, ld := range []bool{false, true} {
		q := typedRequestForTest()
		q.JSONLD = ld
		out, e := s.InspectTypedProduction(t.Context(), q)
		if e != nil || out.BuildError != "" || out.CaptureError != "" || len(out.Calls) != 1 || out.ControllerShape != "set" || len(out.Controllers) != 2 || out.Fields[2].Value.Kind != "double" || out.Fields[3].Value.Kind != "datetime" || out.Fields[3].Value.Text != q.Fields[3].Value.Text {
			t.Fatal(out, e)
		}
		p := out.Calls[0]
		if p.Operation != producerOperation || p.Error != "" || p.CaptureError != "" || p.Version != "1.1" || p.JSONLD != ld || p.IncludeSecret {
			t.Fatal(p)
		}
		wire, e := core.ParseDocumentJSON(p.Output)
		if e != nil {
			t.Fatal(e)
		}
		clock, _ := wire.Get("clock")
		fraction, _ := wire.Get("double")
		text, _ := wire.Get("text")
		controller, _ := wire.Get("controller")
		note, _ := wire.Get("representationNote")
		if clock.Str != "2020-12-20T19:17:47Z" || fraction.Number != "2.0" || text.Str != "한글\n" || len(controller.Array) != 2 || note.Str != "kept" {
			t.Fatal(wire)
		}
		pre, e := core.ParseDocumentJSON(p.Model)
		if e != nil {
			t.Fatal(e)
		}
		original, _ := pre.Get("clock")
		if original.Str != q.Fields[3].Value.Text {
			t.Fatal("pre-input precision normalized", pre)
		}
		_, has := wire.Get("@context")
		if has != ld {
			t.Fatal("wrong actual options")
		}
	}
}
func TestTypedBuilderErrorsNeverBecomeProducerRejection(t *testing.T) {
	s, _ := identify(pinned)
	for _, mutate := range []func(*sageresolution.TypedProductionRequest){
		func(q *sageresolution.TypedProductionRequest) { q.ID = "bad" }, func(q *sageresolution.TypedProductionRequest) { q.Controllers[0] = "bad" },
		func(q *sageresolution.TypedProductionRequest) { q.Fields[0].Value.Kind = "unknown" }, func(q *sageresolution.TypedProductionRequest) { q.Entries[0].Value.Kind = "unknown" },
		func(q *sageresolution.TypedProductionRequest) { q.Fields[2].Value.Text = "NaN" },
	} {
		q := typedRequestForTest()
		mutate(&q)
		out, e := s.InspectTypedProduction(t.Context(), q)
		if e != nil || out.BuildError == "" || len(out.Calls) != 0 {
			t.Fatal(out, e)
		}
	}
}
func TestTypedConstructorAndWitnessControls(t *testing.T) {
	for _, v := range []sageresolution.TypedValue{
		{Kind: "integer", Text: "bad"}, {Kind: "double", Text: "bad"}, {Kind: "datetime", Text: "bad"}, {Kind: "unknown"},
		{Kind: "list", Items: []sageresolution.TypedValue{{Kind: "unknown"}}},
		{Kind: "map", Members: []sageresolution.TypedMember{{Name: "x", Value: sageresolution.TypedValue{Kind: "unknown"}}}},
		{Kind: "map", Members: []sageresolution.TypedMember{{Name: "x", Value: sageresolution.TypedValue{Kind: "null"}}, {Name: "x", Value: sageresolution.TypedValue{Kind: "null"}}}},
	} {
		if _, e := requestedValue(v); e == nil {
			t.Fatal(v)
		}
	}
	// No unsupported actual model is silently assigned a type by the adapter.
	if _, e := actualTypedValue(nil); e == nil {
		t.Fatal("nil type witness")
	}
	for _, v := range []document.Value{document.String(""), document.Integer(-42), document.Double(1.5), document.Boolean(false), document.Null{}, document.NewDateTime(time.Date(2020, 12, 20, 19, 17, 47, 0, time.UTC))} {
		if _, e := actualTypedValue(v); e != nil {
			t.Fatal(v, e)
		}
	}
}
