package didgo

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

type failingMarshaler struct{}

func (failingMarshaler) MarshalJSON() ([]byte, error) { return nil, errFailing }

var errFailing = &json.UnsupportedValueError{Str: "failing"}

func TestMarshalJSON(t *testing.T) {
	if _, err := marshalJSON(failingMarshaler{}); err == nil {
		t.Error("a failing marshaler translated")
	}
	md := document.Metadata{Deactivated: true}
	d, err := marshalJSON(md)
	if err != nil || compact(t, d) != `{"deactivated":true}` {
		t.Errorf("marshalJSON = %s, %v", compact(t, d), err)
	}
}
