package didgo

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// This file translates did-go's data model into the inspector's neutral
// JSON form. It writes every property did-go holds under the name the
// specifications give it, in the order did-go's producer writes them, and
// adds nothing: the inspector, not the adapter, interprets the result.

// documentJSON returns the data model entries of d: the core properties
// and the extensions. Representation-specific entries are not included;
// representationEntries returns them.
func documentJSON(d *document.Document) (core.DocumentJSON, error) {
	var out []core.Member
	add := func(name string, v core.Value) { out = append(out, core.M(name, v)) }
	add("id", core.String(d.ID().String()))
	if cs := d.Controllers(); len(cs) > 0 || d.ControllerShape() == vm.ShapeSet {
		items := make([]core.Value, len(cs))
		for i, c := range cs {
			items[i] = core.String(c.String())
		}
		add("controller", shaped(d.ControllerShape(), items))
	}
	if aka := d.AlsoKnownAs(); aka != nil {
		add("alsoKnownAs", stringArray(aka))
	}
	if ms := d.VerificationMethods(); ms != nil {
		items := make([]core.Value, len(ms))
		for i, m := range ms {
			v, err := methodJSON(m)
			if err != nil {
				return core.DocumentJSON{}, fmt.Errorf("verificationMethod[%d]: %w", i, err)
			}
			items[i] = v
		}
		add("verificationMethod", core.Array(items...))
	}
	for _, p := range vm.Purposes() {
		rs := d.Relationship(p)
		if rs == nil {
			continue
		}
		items := make([]core.Value, len(rs))
		for i, r := range rs {
			v, err := relationshipJSON(r)
			if err != nil {
				return core.DocumentJSON{}, fmt.Errorf("%s[%d]: %w", p, i, err)
			}
			items[i] = v
		}
		add(p.String(), core.Array(items...))
	}
	if ss := d.Services(); ss != nil {
		items := make([]core.Value, len(ss))
		for i, sv := range ss {
			v, err := serviceJSON(sv)
			if err != nil {
				return core.DocumentJSON{}, fmt.Errorf("service[%d]: %w", i, err)
			}
			items[i] = v
		}
		add("service", core.Array(items...))
	}
	for _, e := range d.Extensions().Entries() {
		v, err := valueJSON(e.Value)
		if err != nil {
			return core.DocumentJSON{}, fmt.Errorf("%s: %w", e.Key, err)
		}
		add(e.Key, v)
	}
	return core.NewDocument(out...), nil
}

// representationEntries returns the representation-specific entries did-go
// kept for d, such as @context.
func representationEntries(d *document.Document) (core.DocumentJSON, error) {
	v, err := mapJSON(d.RepresentationEntries())
	if err != nil {
		return core.DocumentJSON{}, err
	}
	return core.NewDocument(v.Object...), nil
}

// fullDocumentJSON returns the representation-specific entries followed by
// the data model entries: everything did-go returned for a document.
func fullDocumentJSON(d *document.Document) (core.DocumentJSON, error) {
	repr, err := representationEntries(d)
	if err != nil {
		return core.DocumentJSON{}, err
	}
	model, err := documentJSON(d)
	if err != nil {
		return core.DocumentJSON{}, err
	}
	return core.NewDocument(append(repr.Members, model.Members...)...), nil
}

func shaped(s vm.Shape, items []core.Value) core.Value {
	if s.Resolve(len(items)) == vm.ShapeSingle && len(items) == 1 {
		return items[0]
	}
	return core.Array(items...)
}

func stringArray(ss []string) core.Value {
	items := make([]core.Value, len(ss))
	for i, s := range ss {
		items[i] = core.String(s)
	}
	return core.Array(items...)
}

func relationshipJSON(r vm.Relationship) (core.Value, error) {
	if m, ok := r.Method(); ok {
		return methodJSON(m)
	}
	ref, _ := r.Reference()
	return core.String(ref.String()), nil
}

// methodJSON writes a verification method with every property did-go
// holds, secret key material included, so that nothing did-go returned is
// hidden from the inspector.
func methodJSON(m vm.Method) (core.Value, error) {
	var out []core.Member
	add := func(name string, v core.Value) { out = append(out, core.M(name, v)) }
	add("id", core.String(m.ID.String()))
	add("type", core.String(m.Type))
	add("controller", core.String(m.Controller.String()))
	if m.Expires != nil {
		add("expires", core.String(spec.FormatTimestamp(*m.Expires)))
	}
	if m.Revoked != nil {
		add("revoked", core.String(spec.FormatTimestamp(*m.Revoked)))
	}
	if m.PublicKeyMultibase != "" {
		add("publicKeyMultibase", core.String(m.PublicKeyMultibase))
	}
	if m.PublicKeyJwk != nil {
		v, err := anyJSON(m.PublicKeyJwk)
		if err != nil {
			return core.Value{}, fmt.Errorf("publicKeyJwk: %w", err)
		}
		add("publicKeyJwk", v)
	}
	if m.SecretKeyMultibase != "" {
		add("secretKeyMultibase", core.String(m.SecretKeyMultibase))
	}
	if m.SecretKeyJwk != nil {
		v, err := anyJSON(m.SecretKeyJwk)
		if err != nil {
			return core.Value{}, fmt.Errorf("secretKeyJwk: %w", err)
		}
		add("secretKeyJwk", v)
	}
	extra, err := extraJSON(m.Extra)
	if err != nil {
		return core.Value{}, err
	}
	return core.Object(append(out, extra...)...), nil
}

func serviceJSON(s vm.Service) (core.Value, error) {
	var out []core.Member
	if s.ID != "" {
		out = append(out, core.M("id", core.String(s.ID)))
	}
	types := make([]core.Value, len(s.Type))
	for i, t := range s.Type {
		types[i] = core.String(t)
	}
	out = append(out, core.M("type", shaped(s.TypeShape, types)))
	eps := make([]core.Value, len(s.ServiceEndpoint))
	for i, e := range s.ServiceEndpoint {
		if e.Map == nil {
			eps[i] = core.String(e.URL)
			continue
		}
		v, err := anyJSON(e.Map)
		if err != nil {
			return core.Value{}, fmt.Errorf("serviceEndpoint[%d]: %w", i, err)
		}
		eps[i] = v
	}
	out = append(out, core.M("serviceEndpoint", shaped(s.EndpointShape, eps)))
	extra, err := extraJSON(s.Extra)
	if err != nil {
		return core.Value{}, err
	}
	return core.Object(append(out, extra...)...), nil
}

// extraJSON writes additional properties sorted by name, as did-go's
// producer does.
func extraJSON(extra map[string]any) ([]core.Member, error) {
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]core.Member, 0, len(keys))
	for _, k := range keys {
		v, err := anyJSON(extra[k])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out = append(out, core.M(k, v))
	}
	return out, nil
}

// valueJSON translates a value of did-go's data model.
func valueJSON(v document.Value) (core.Value, error) {
	switch t := v.(type) {
	case document.String:
		return core.String(string(t)), nil
	case document.Integer:
		return core.Number(strconv.FormatInt(int64(t), 10)), nil
	case document.Double:
		return doubleJSON(float64(t))
	case document.Boolean:
		return core.Bool(bool(t)), nil
	case document.Null:
		return core.Null(), nil
	case document.DateTime:
		return core.String(spec.FormatTimestamp(t.Time())), nil
	case document.List:
		items := make([]core.Value, t.Len())
		for i, it := range t.Items() {
			x, err := valueJSON(it)
			if err != nil {
				return core.Value{}, fmt.Errorf("[%d]: %w", i, err)
			}
			items[i] = x
		}
		return core.Array(items...), nil
	case document.Map:
		return mapJSON(t)
	}
	return core.Value{}, fmt.Errorf("value of type %T has no JSON form", v)
}

func mapJSON(m document.Map) (core.Value, error) {
	entries := m.Entries()
	out := make([]core.Member, len(entries))
	for i, e := range entries {
		x, err := valueJSON(e.Value)
		if err != nil {
			return core.Value{}, fmt.Errorf("%s: %w", e.Key, err)
		}
		out[i] = core.M(e.Key, x)
	}
	return core.Object(out...), nil
}

// doubleJSON writes a double so that it reads back as a double: with a
// decimal point or an exponent.
func doubleJSON(f float64) (core.Value, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return core.Value{}, fmt.Errorf("double %v is not finite", f)
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return core.Number(s), nil
}

// anyJSON translates a JSON value held as Go values (map[string]any, []any,
// json.Number, strings, booleans, numbers, nil), as did-go keeps additional
// properties, JSON Web Keys and metadata. Map members are sorted by name,
// since a Go map has no order.
func anyJSON(v any) (core.Value, error) {
	switch t := v.(type) {
	case nil:
		return core.Null(), nil
	case bool:
		return core.Bool(t), nil
	case string:
		return core.String(t), nil
	case json.Number:
		return core.Number(t.String()), nil
	case float64:
		return doubleJSON(t)
	case float32:
		return doubleJSON(float64(t))
	case int:
		return core.Number(strconv.Itoa(t)), nil
	case int64:
		return core.Number(strconv.FormatInt(t, 10)), nil
	case time.Time:
		return core.String(spec.FormatTimestamp(t)), nil
	case []any:
		items := make([]core.Value, len(t))
		for i, it := range t {
			x, err := anyJSON(it)
			if err != nil {
				return core.Value{}, fmt.Errorf("[%d]: %w", i, err)
			}
			items[i] = x
		}
		return core.Array(items...), nil
	case []string:
		return stringArray(t), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		out := make([]core.Member, len(keys))
		for i, k := range keys {
			x, err := anyJSON(t[k])
			if err != nil {
				return core.Value{}, fmt.Errorf("%s: %w", k, err)
			}
			out[i] = core.M(k, x)
		}
		return core.Object(out...), nil
	case document.Value:
		return valueJSON(t)
	}
	return core.Value{}, fmt.Errorf("value of type %T has no JSON form", v)
}

// marshalJSON translates a did-go value with a JSON encoding of its own
// (metadata structures) by parsing that encoding.
func marshalJSON(v json.Marshaler) (core.DocumentJSON, error) {
	data, err := v.MarshalJSON()
	if err != nil {
		return core.DocumentJSON{}, err
	}
	return core.ParseDocumentJSON(data)
}
