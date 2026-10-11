package checks

import (
	"math"
	"testing"
)

func TestBindingRequest(t *testing.T) {
	for _, tc := range []struct {
		method, input, accept string
		opts                  map[string]any
		target, body          string
	}{
		{"GET", "did:example:1234", MediaTypeDIDResolution, nil, "did:example:1234", ""},
		{"GET", "did:example:1234?service=files&relativeRef=/resume.pdf", MediaTypeDIDURLDereferencing, map[string]any{"accept": "x/y"},
			"did:example:1234?service=files&relativeRef=/resume.pdf", ""},
		{"GET", "did:example:1234", MediaTypeDIDResolution, map[string]any{"option2": "value2", "option1": "value1"},
			"did%3Aexample%3A1234?option1=value1&option2=value2", ""},
		{"GET", "did:example:1234?service=files&relativeRef=/resume.pdf", MediaTypeDIDURLDereferencing, map[string]any{"noCache": true, "n": 1.5},
			"did%3Aexample%3A1234%3Fservice%3Dfiles%26relativeRef%3D%2Fresume.pdf?n=1.5&noCache=true", ""},
		{"GET", "did:example:1234#key-1", "", nil, "did%3Aexample%3A1234%23key-1", ""},
		{"POST", "did:example:1234", MediaTypeDIDResolution, map[string]any{"option1": "value1"}, "did:example:1234", `{"option1":"value1"}`},
		{"POST", "did:example:1234#k", MediaTypeDIDURLDereferencing, nil, "did%3Aexample%3A1234%23k", ""},
	} {
		req, err := BindingRequest(tc.method, tc.input, tc.accept, tc.opts)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.input, err)
		}
		if req.Method != tc.method || req.Target != tc.target || string(req.Body) != tc.body || req.Header.Get("Accept") != tc.accept {
			t.Errorf("%s %s %v: got %+v body %s", tc.method, tc.input, tc.opts, req, req.Body)
		}
		if (tc.body != "") != (req.Header.Get("Content-Type") == "application/json") {
			t.Errorf("%s %s: content type %q", tc.method, tc.input, req.Header.Get("Content-Type"))
		}
	}
	if _, err := BindingRequest("PUT", "did:example:1", "", nil); err == nil {
		t.Error("PUT accepted")
	}
	if _, err := BindingRequest("GET", "did:example:1", "", map[string]any{"x": math.Inf(1)}); err == nil {
		t.Error("unencodable query option accepted")
	}
	if _, err := BindingRequest("POST", "did:example:1", "", map[string]any{"x": math.Inf(1)}); err == nil {
		t.Error("unencodable body option accepted")
	}
	if BindingStatus["https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED"] != 406 || len(BindingStatus) != 9 {
		t.Errorf("table = %v", BindingStatus)
	}
}
