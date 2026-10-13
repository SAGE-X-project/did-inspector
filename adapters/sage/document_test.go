package sage

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/vm"
)

func TestMethodJSON(t *testing.T) {
	id, err := did.ParseURL("did:example:1#k")
	if err != nil {
		t.Fatal(err)
	}
	ctl, _ := did.Parse("did:example:1")
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	m := vm.Method{ID: id, Type: "X", Controller: ctl, Expires: &at, Revoked: &at,
		PublicKeyMultibase: "zpub", PublicKeyJwk: map[string]any{"kty": "OKP"},
		SecretKeyMultibase: "zsec", SecretKeyJwk: map[string]any{"d": "x"},
		Extra: map[string]any{"b": json.Number("1"), "a": []any{true, nil}}}
	v, err := methodJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"did:example:1#k","type":"X","controller":"did:example:1","expires":"2030-01-02T03:04:05Z","revoked":"2030-01-02T03:04:05Z","publicKeyMultibase":"zpub","publicKeyJwk":{"kty":"OKP"},"secretKeyMultibase":"zsec","secretKeyJwk":{"d":"x"},"a":[true,null],"b":1}`
	if got := compact(t, v); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	for _, bad := range []vm.Method{
		{PublicKeyJwk: map[string]any{"x": struct{}{}}},
		{SecretKeyJwk: map[string]any{"x": struct{}{}}},
		{Extra: map[string]any{"x": struct{}{}}},
	} {
		if _, err := methodJSON(bad); err == nil {
			t.Errorf("method %+v translated", bad)
		}
	}
	if _, err := relationshipJSON(vm.Embed(vm.Method{Extra: map[string]any{"x": struct{}{}}})); err == nil {
		t.Error("embedded method with an untranslatable value translated")
	}
}

func TestServiceJSON(t *testing.T) {
	s := vm.Service{Type: []string{"A"}, TypeShape: vm.ShapeSet,
		ServiceEndpoint: []vm.Endpoint{{URL: "https://example.com/"}}, EndpointShape: vm.ShapeSingle}
	v, err := serviceJSON(s)
	if err != nil || compact(t, v) != `{"type":["A"],"serviceEndpoint":"https://example.com/"}` {
		t.Errorf("serviceJSON = %s, %v", compact(t, v), err)
	}
	for _, bad := range []vm.Service{
		{ServiceEndpoint: []vm.Endpoint{{Map: map[string]any{"x": struct{}{}}}}},
		{Extra: map[string]any{"x": struct{}{}}},
	} {
		if _, err := serviceJSON(bad); err == nil {
			t.Errorf("service %+v translated", bad)
		}
	}
}

func TestValueJSON(t *testing.T) {
	inner, _ := document.NewMap(document.Entry{Key: "k", Value: document.Boolean(true)})
	list, _ := document.NewList(document.String("s"), document.Integer(-3), document.Double(2), document.Null{},
		document.NewDateTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)), inner)
	v, err := valueJSON(list)
	if err != nil || compact(t, v) != `["s",-3,2.0,null,"2020-01-01T00:00:00Z",{"k":true}]` {
		t.Errorf("valueJSON = %s, %v", compact(t, v), err)
	}
	nan, _ := document.NewList(document.Double(math.NaN()))
	if _, err := valueJSON(nan); err == nil {
		t.Error("NaN translated")
	}
	bad, _ := document.NewMap(document.Entry{Key: "k", Value: nan})
	if _, err := valueJSON(bad); err == nil {
		t.Error("map with NaN translated")
	}
	if _, err := valueJSON(nil); err == nil {
		t.Error("nil value translated")
	}
}

func TestAnyJSON(t *testing.T) {
	v, err := anyJSON(map[string]any{
		"z": float64(1.25), "y": float32(0.5), "x": 3, "w": int64(4), "v": []string{"a"},
		"u": time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), "t": document.String("d"), "s": false, "r": float64(7),
	})
	want := `{"r":7.0,"s":false,"t":"d","u":"2020-01-01T00:00:00Z","v":["a"],"w":4,"x":3,"y":0.5,"z":1.25}`
	if err != nil || compact(t, v) != want {
		t.Errorf("anyJSON = %s, %v", compact(t, v), err)
	}
	for _, bad := range []any{struct{}{}, []any{struct{}{}}, map[string]any{"a": struct{}{}}, math.Inf(1)} {
		if _, err := anyJSON(bad); err == nil {
			t.Errorf("anyJSON(%v) translated", bad)
		}
	}
}

func compact(t *testing.T, v interface{ MarshalJSON() ([]byte, error) }) string {
	t.Helper()
	b, err := v.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDocumentSnapshotPreservesActualAccessors(t *testing.T) {
	id, _ := did.Parse("did:example:1")
	key, _ := did.ParseURL("did:example:1#k")
	method := vm.Method{ID: key, Type: "ExampleKey", Controller: id, PublicKeyMultibase: "zpub"}
	list, _ := document.NewList(document.Integer(1), document.Double(2), document.Boolean(true), document.Null{})
	at := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.FixedZone("fixture", 9*60*60))
	b := document.NewBuilder(id).Controller(id).ControllerShape(vm.ShapeSet).AlsoKnownAs("https://example.org/me").
		VerificationMethod(method).Relationship(vm.Authentication, vm.Ref(key)).
		Relationship(vm.AssertionMethod, vm.Embed(method)).
		Service(vm.Service{ID: "did:example:1#s", Type: []string{"A", "B"}, TypeShape: vm.ShapeSet,
			ServiceEndpoint: []vm.Endpoint{{URL: "https://example.org/a"}, {Map: map[string]any{"uri": "https://example.org/b"}}}, EndpointShape: vm.ShapeSet, Extra: map[string]any{"note": true}}).
		Extension("values", list).Extension("clock", document.NewDateTime(at)).
		RepresentationEntry("@context", document.String("https://www.w3.org/ns/did/v1.1"))
	doc, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := documentSnapshot(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Expectations are written independently of the subject's producer/validator.
	want := `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:1","controller":["did:example:1"],"alsoKnownAs":["https://example.org/me"],"verificationMethod":[{"id":"did:example:1#k","type":"ExampleKey","controller":"did:example:1","publicKeyMultibase":"zpub"}],"authentication":["did:example:1#k"],"assertionMethod":[{"id":"did:example:1#k","type":"ExampleKey","controller":"did:example:1","publicKeyMultibase":"zpub"}],"service":[{"id":"did:example:1#s","type":["A","B"],"serviceEndpoint":["https://example.org/a",{"uri":"https://example.org/b"}],"note":true}],"values":[1,2.0,true,null],"clock":"2030-01-02T03:04:05.123456789+09:00"}`
	if string(raw) != want {
		t.Fatalf("native capture changed data:\n%s\n%s", raw, want)
	}
	// Explicit empty sets must survive instead of becoming omitted properties.
	empty, err := document.NewBuilder(id).ControllerShape(vm.ShapeSet).VerificationMethod().Service().Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err = documentSnapshot(empty)
	if err != nil || string(raw) != `{"id":"did:example:1","controller":[],"verificationMethod":[],"service":[]}` {
		t.Fatal(string(raw), err)
	}
}

func TestNativeCaptureDoesNotTruncateDates(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.FixedZone("fixture", 9*60*60))
	m := vm.Method{Expires: &at, Revoked: &at}
	v, err := methodJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"expires", "revoked"} {
		got, _ := v.Get(field)
		if got.Str != "2030-01-02T03:04:05.123456789+09:00" {
			t.Fatal("date normalized", got)
		}
	}
	v, err = anyJSON(at)
	if err != nil || v.Str != "2030-01-02T03:04:05.123456789+09:00" {
		t.Fatal(v, err)
	}
}
