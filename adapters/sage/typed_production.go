package sage

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func requestedValue(v sageresolution.TypedValue) (document.Value, error) {
	switch v.Kind {
	case "string":
		return document.String(v.Text), nil
	case "integer":
		n, e := strconv.ParseInt(v.Text, 10, 64)
		return document.Integer(n), e
	case "double":
		n, e := strconv.ParseFloat(v.Text, 64)
		return document.Double(n), e
	case "boolean":
		return document.Boolean(v.Flag), nil
	case "null":
		return document.Null{}, nil
	case "datetime":
		t, e := time.Parse(time.RFC3339Nano, v.Text)
		return document.NewDateTime(t), e
	case "list":
		items := []document.Value{}
		for _, item := range v.Items {
			value, e := requestedValue(item)
			if e != nil {
				return nil, e
			}
			items = append(items, value)
		}
		return document.NewList(items...)
	case "map":
		members := []document.Entry{}
		for _, m := range v.Members {
			value, e := requestedValue(m.Value)
			if e != nil {
				return nil, e
			}
			members = append(members, document.Entry{Key: m.Name, Value: value})
		}
		return document.NewMap(members...)
	}
	return nil, fmt.Errorf("unsupported requested type %q", v.Kind)
}
func actualTypedValue(v document.Value) (sageresolution.TypedValue, error) {
	out := sageresolution.TypedValue{}
	switch value := v.(type) {
	case document.String:
		out.Kind, out.Text = "string", string(value)
	case document.Integer:
		out.Kind, out.Text = "integer", strconv.FormatInt(int64(value), 10)
	case document.Double:
		out.Kind, out.Text = "double", strconv.FormatFloat(float64(value), 'f', -1, 64)
	case document.Boolean:
		out.Kind, out.Flag = "boolean", bool(value)
	case document.Null:
		out.Kind = "null"
	case document.DateTime:
		out.Kind, out.Text = "datetime", value.Time().Format(time.RFC3339Nano)
	case document.List:
		out.Kind = "list"
		for _, item := range value.Items() {
			x, e := actualTypedValue(item)
			if e != nil {
				return out, e
			}
			out.Items = append(out.Items, x)
		}
	case document.Map:
		out.Kind = "map"
		for _, item := range value.Entries() {
			x, e := actualTypedValue(item.Value)
			if e != nil {
				return out, e
			}
			out.Members = append(out.Members, sageresolution.TypedMember{Name: item.Key, Value: x})
		}
	default:
		return out, fmt.Errorf("unsupported actual model type %T", v)
	}
	return out, nil
}
func actualTypedMembers(m document.Map) ([]sageresolution.TypedMember, error) {
	out := []sageresolution.TypedMember{}
	for _, item := range m.Entries() {
		v, e := actualTypedValue(item.Value)
		if e != nil {
			return nil, e
		}
		out = append(out, sageresolution.TypedMember{Name: item.Key, Value: v})
	}
	return out, nil
}

// InspectTypedProduction uses typed constructors rather than a subject consumer
// to create the input. Actual type witnesses are captured from the built model
// before the unchanged pinned producer is invoked. Build failures are distinct
// from actual producer rejection; no validator findings supply a verdict.
func (s *Subject) InspectTypedProduction(_ context.Context, q sageresolution.TypedProductionRequest) (sageresolution.TypedProductionResult, error) {
	out := sageresolution.TypedProductionResult{}
	fail := func(e error) (sageresolution.TypedProductionResult, error) {
		out.BuildError = e.Error()
		return out, nil
	}
	id, e := did.Parse(q.ID)
	if e != nil {
		return fail(e)
	}
	b := document.NewBuilder(id)
	switch q.ControllerShape {
	case "", "set":
		b.ControllerShape(vm.ShapeSet)
	case "absent":
		if len(q.Controllers) != 0 {
			return fail(fmt.Errorf("absent controller property cannot have values"))
		}
	default:
		return fail(fmt.Errorf("unsupported explicit controller shape %q", q.ControllerShape))
	}
	for _, c := range q.Controllers {
		ctl, e := did.Parse(c)
		if e != nil {
			return fail(e)
		}
		b.Controller(ctl)
	}
	for _, m := range q.Fields {
		v, e := requestedValue(m.Value)
		if e != nil {
			return fail(e)
		}
		b.Extension(m.Name, v)
	}
	for _, m := range q.Entries {
		v, e := requestedValue(m.Value)
		if e != nil {
			return fail(e)
		}
		b.RepresentationEntry(m.Name, v)
	}
	d, e := b.Build()
	if e != nil {
		return fail(e)
	}
	out.ID, out.ControllerShape = d.ID().String(), d.ControllerShape().String()
	for _, c := range d.Controllers() {
		out.Controllers = append(out.Controllers, c.String())
	}
	out.Fields, e = actualTypedMembers(d.Extensions())
	if e != nil {
		out.CaptureError = e.Error()
		return out, nil
	}
	out.Entries, e = actualTypedMembers(d.RepresentationEntries())
	if e != nil {
		out.CaptureError = e.Error()
		return out, nil
	}
	version := spec.V11
	switch q.Version {
	case "", "1.1":
	case "1.0":
		version = spec.V10
	default:
		return fail(fmt.Errorf("unsupported explicit production version %q", q.Version))
	}
	_, _, _ = (observedProducer{producer.New(), &out.Calls}).Produce(d, representation.ProduceOptions{Version: version, JSONLD: q.JSONLD})
	return out, nil
}
