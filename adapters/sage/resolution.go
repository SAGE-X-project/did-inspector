package sage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"

	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution/compat"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/adapters/https"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// ResolutionIdentity separates this observation scope from projection reports.
func (s *Subject) ResolutionIdentity() *Subject {
	copy := *s
	copy.info.Name = "did-go/advanced/sage-resolution"
	return &copy
}

type resolutionSource struct {
	record  didsage.Record
	failure string
}

func (s resolutionSource) Observe(_ context.Context, d did.DID) (didsage.Record, error) {
	if s.failure != "" {
		return didsage.Record{}, didsage.NewError(didsage.Code(s.failure), "explicit inspector source fixture")
	}
	if d != s.record.DID {
		return didsage.Record{}, didsage.NewError(didsage.CodeRecordNotFound, "")
	}
	return s.record, nil
}

func resolutionRecord(in sageprojection.Record) (didsage.Record, error) {
	d, err := did.Parse(in.DID)
	if err != nil {
		return didsage.Record{}, err
	}
	issued := int64(1799999000)
	r := didsage.Record{DID: d, Controller: "fixture-controller", State: didsage.State(in.State), Version: in.Version,
		Services:    []didsage.Service{{Name: "a2a", Type: "A2AInterface", URI: "https://agent.example/a2a"}},
		Observation: didsage.Observation{Issued: &issued, Time: 1800000000, Source: "inspector-fixture-only"}}
	for _, k := range in.Keys {
		b, e := hex.DecodeString(k.MaterialHex)
		if e != nil {
			return r, e
		}
		r.Keys = append(r.Keys, didsage.Key{Name: k.Name, Alg: k.Algorithm, Material: b, State: didsage.KeyState(k.State), Expires: k.Expires})
	}
	return r, nil
}

// InspectResolution calls the actual pinned players. No SAGE error, metadata
// member or expected document is repaired or inserted by this adapter.
func (s *Subject) InspectResolution(ctx context.Context, in sageprojection.Record, q sageresolution.Request) (sageresolution.Result, error) {
	out := sageresolution.Result{}
	rec, err := resolutionRecord(in)
	if err != nil {
		return out, err
	}
	r, err := didsage.NewResolver(resolutionSource{rec, q.SourceFailure}, consumer.New(), producer.New())
	if err != nil {
		return out, err
	}
	ro, do := nativeOptions(q)
	switch q.Function {
	case "http", "http-comparison":
		if q.HTTP == nil {
			return out, errors.New("missing inspector HTTP request")
		}
		srv := httptest.NewTLSServer(didsage.NewHandler(r, universal.DefaultPathPrefix, universal.WithProducer(producer.New())))
		defer srv.Close()
		remote, e := https.New(srv.URL+universal.DefaultPathPrefix, https.WithClient(srv.Client()))
		if e != nil {
			return out, e
		}
		ex, e := remote.Exchange(ctx, *q.HTTP)
		out.Exchange = &ex
		if e != nil || q.Function != "http-comparison" {
			return out, e
		}
		if q.NativeFunction != "resolve" && q.NativeFunction != "dereference" {
			return out, errors.New("comparison requires an explicit native operation")
		}
		nativeRequest := q
		nativeRequest.Function, nativeRequest.NativeFunction, nativeRequest.HTTP = q.NativeFunction, "", nil
		native, err := s.InspectResolution(ctx, in, nativeRequest)
		if err != nil {
			return out, err
		}
		out.Native = &sageresolution.NativeObservation{Request: nativeRequest, Result: &native}
		return out, nil
	case "resolve":
		res, code := r.ResolveString(ctx, q.Input, ro)
		out.SageCode = string(code)
		out.Raw = res.Raw
		out.HasContent = res.Document != nil
		if res.Document != nil {
			out.ReturnedID = res.Document.ID().String()
			out.ContentKind = "document"
			out.Snapshot, err = documentSnapshot(res.Document)
			if err != nil {
				return out, err
			}
		}
		return nativeResult(out, res.ResolutionMetadata, res.DocumentMetadata)
	case "resolve10", "representation10":
		d, e := did.Parse(q.Input)
		if e != nil {
			return out, e
		}
		v := compat.V10Resolver{Inner: r}
		if q.Function == "representation10" {
			md, b, dm := v.ResolveRepresentation(ctx, d, ro)
			out.Raw = b
			out.HasContent = len(b) > 0
			return nativeResult(out, md, dm)
		}
		md, doc, dm := v.Resolve(ctx, d, ro)
		out.HasContent = doc != nil
		if doc != nil {
			out.ReturnedID = doc.ID().String()
			out.ContentKind = "document"
			out.Snapshot, err = documentSnapshot(doc)
			if err != nil {
				return out, err
			}
		}
		return nativeResult(out, md, dm)
	case "dereference", "dereference10":
		u, e := did.ParseURL(q.Input)
		if e != nil {
			return out, e
		}
		if q.Function == "dereference10" {
			md, c, dm := (&compat.V10Dereferencer{Inner: r}).Dereference(ctx, u, do)
			return dereferenceResult(out, md, c, dm)
		}
		res, code := r.DereferenceWithCode(ctx, u, do)
		out.SageCode = string(code)
		return dereferenceResult(out, res.DereferencingMetadata, res.ContentStream, res.ContentMetadata)
	default:
		return out, errors.New("unknown resolution operation")
	}
}

func nativeResult(out sageresolution.Result, md any, dm document.Metadata) (sageresolution.Result, error) {
	var err error
	out.Metadata, err = json.Marshal(md)
	if err != nil {
		return out, err
	}
	out.ContentMetadata, err = json.Marshal(dm)
	return out, err
}
func dereferenceResult(out sageresolution.Result, md any, c any, dm document.Metadata) (sageresolution.Result, error) {
	var err error
	out.HasContent = c != nil
	switch v := c.(type) {
	case *document.Document:
		out.ReturnedID = v.ID().String()
		out.ContentKind = "document"
		out.Snapshot, err = documentSnapshot(v)
	case vm.Method:
		out.ReturnedID = v.ID.String()
		out.ContentKind = "verification-method"
		value, e := methodJSON(v)
		if e != nil {
			return out, e
		}
		out.Snapshot, err = value.MarshalJSON()
	}
	if err != nil {
		return out, err
	}
	// This JSON captures the native data model, not a produced representation.
	b := out.Snapshot
	if c == nil {
		b = []byte("null")
	}
	if b == nil {
		b, err = json.Marshal(c)
	}
	if err != nil {
		return out, err
	}
	out.Raw = b
	return nativeResult(out, md, dm)
}
