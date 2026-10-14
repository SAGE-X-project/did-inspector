package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestNativeResourceKindsAndCaptureErrors(t *testing.T) {
	service := vm.Service{ID: "#one", Type: []string{"Messaging"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://agent.example/base/"}}}
	m, _ := document.NewMap(document.Entry{Key: "id", Value: document.String("#nested")}, document.Entry{Key: "label", Value: document.String("value")})
	for _, tt := range []struct {
		value    any
		kind, id string
	}{{service, "service", "#one"}, {m, "map", "#nested"}, {[]string{"https://agent.example/base/"}, "uri-list", ""}, {document.Map{}, "map", ""}} {
		v, e := dereferenceResult(sageresolution.Result{}, nil, tt.value, document.Metadata{})
		if e != nil || v.ContentKind != tt.kind || v.ReturnedID != tt.id || !v.HasContent || !json.Valid(v.Raw) {
			t.Fatal(v, e)
		}
	}
	service.Extra = map[string]any{"bad": func() {}}
	if _, e := dereferenceResult(sageresolution.Result{}, nil, service, document.Metadata{}); e == nil {
		t.Fatal("capture error lost")
	}
	m, _ = document.NewMap(document.Entry{Key: "id", Value: document.Integer(1)})
	v, e := dereferenceResult(sageresolution.Result{}, nil, m, document.Metadata{})
	if e != nil || v.ReturnedID != "" {
		t.Fatal("invented string id", v, e)
	}
}
