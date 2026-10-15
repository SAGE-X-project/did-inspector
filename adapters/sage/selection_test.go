package sage

import (
	"bytes"
	"encoding/json"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualSelectionAndOriginalResolvedModels(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/selection-source-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				var capture map[string]json.RawMessage
				_ = json.Unmarshal([]byte(o.Observed), &capture)
				t.Fatal(o.Statement, o.Verdict, string(capture["runtime"]))
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}

func TestOriginalResolutionCaptureIsPassive(t *testing.T) {
	id, err := did.Parse("did:example:resources")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := document.NewBuilder(id).Build()
	if err != nil {
		t.Fatal(err)
	}
	model, entries, _ := captureMaps(doc)
	original := resolution.Result{Document: doc, Raw: []byte(`{"public":"unchanged"}`), ResolutionMetadata: resolution.ResolutionMetadata{ContentType: "application/did"}}
	out := sageresolution.RoutingResult{}
	got := (routingResolver{fragmentResolveValue{original}, &out}).Resolve(t.Context(), id, resolution.ResolutionOptions{})
	if got.Document != doc || !bytes.Equal(got.Raw, original.Raw) || !bytes.Equal(out.ResolvedDataModel, model) || !bytes.Equal(out.ResolvedEntries, entries) || string(out.ResolvedMetadata) != `{"contentType":"application/did"}` || out.CaptureError != "" {
		t.Fatal("delegate or original capture changed")
	}
	out.DataModel[0] = '!'
	out.Entries[0] = '!'
	if !bytes.Equal(out.ResolvedDataModel, model) || !bytes.Equal(out.ResolvedEntries, entries) {
		t.Fatal("snapshot aliases final maps")
	}
	original.ResolutionMetadata.Extra = map[string]any{"metadataFailure": func() {}}
	out = sageresolution.RoutingResult{}
	got = (routingResolver{fragmentResolveValue{original}, &out}).Resolve(t.Context(), id, resolution.ResolutionOptions{Extra: map[string]any{"optionFailure": func() {}}})
	if got.Document != doc || !bytes.Equal(got.Raw, original.Raw) || len(out.ResolvedMetadata) != 0 || !bytes.Equal(out.ResolvedDataModel, model) || !strings.Contains(out.CaptureError, "metadataFailure") || !strings.Contains(out.CaptureError, "optionFailure") || !strings.Contains(out.CaptureError, "\n") {
		t.Fatal("earlier capture error lost", out.CaptureError)
	}
	for _, x := range []struct{ first, next, want string }{{"", "", ""}, {"first", "", "first"}, {"", "next", "next"}, {"first", "next", "first\nnext"}} {
		if joinRoutingCapture(x.first, x.next) != x.want {
			t.Fatal(x)
		}
	}
}
