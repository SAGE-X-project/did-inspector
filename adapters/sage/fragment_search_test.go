package sage

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualFragmentSearchAndFixtureInitialState(t *testing.T) {
	s, _ := sourceTest(t)
	p, err := sageresolution.Profile("did-1.1")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range p.Cases {
		initial := strings.Contains(c.ID, "/fragment-initial-")
		search := strings.Contains(c.ID, "/fragment-search-")
		if !initial && !search {
			continue
		}
		count++
		want := core.Pass
		if search && !strings.HasSuffix(c.ID, "extension-list") {
			want = core.Fail
		}
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != want {
				t.Fatal(c.ID, o.Statement, o.Verdict, o.Observed)
			}
			if search {
				var values []sageresolution.RoutingResult
				if json.Unmarshal([]byte(o.Observed), &values) != nil || len(values) != 3 {
					t.Fatal("receipts")
				}
				for _, v := range values {
					if len(v.DataModel) == 0 || len(v.Entries) == 0 || len(v.ResolveInputs) != 1 {
						t.Fatal("same-call pre-search document missing")
					}
				}
			}
		}
	}
	if count != 6 {
		t.Fatal("case inventory", count)
	}
}

type fragmentResolveValue struct{ value resolution.Result }

func (s fragmentResolveValue) Resolve(context.Context, did.DID, resolution.ResolutionOptions) resolution.Result {
	return s.value
}
func TestNestedResolverCapturePreservesDocumentIdentity(t *testing.T) {
	id, err := did.Parse("did:example:resources")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := document.NewBuilder(id).Build()
	if err != nil {
		t.Fatal(err)
	}
	original := resolution.Result{Document: doc, Raw: []byte(`{"unchanged":"delegate bytes"}`)}
	beforeModel, beforeEntries, captureError := captureMaps(doc)
	if captureError != "" {
		t.Fatal(captureError)
	}
	out := sageresolution.RoutingResult{}
	wrapper := routingResolver{fragmentResolveValue{original}, &out}
	got := wrapper.Resolve(t.Context(), id, resolution.ResolutionOptions{})
	afterModel, afterEntries, _ := captureMaps(doc)
	if got.Document != doc || !bytes.Equal(got.Raw, original.Raw) || !bytes.Equal(beforeModel, afterModel) || !bytes.Equal(beforeEntries, afterEntries) || !bytes.Equal(out.DataModel, beforeModel) || !bytes.Equal(out.Entries, beforeEntries) || out.CaptureError != "" {
		t.Fatal("passive capture changed delegate or document")
	}
}
