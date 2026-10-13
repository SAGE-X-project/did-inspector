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
	"github.com/sage-x-project/did-go/resolution"
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
	ro := resolution.ResolutionOptions{Accept: q.Accept}
	do := resolution.DereferenceOptions{Accept: q.Accept, VerificationRelationship: q.Relationship}
	switch q.Function {
	case "http":
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
		return out, e
	case "resolve":
		res, code := r.ResolveString(ctx, q.Input, ro)
		out.SageCode = string(code)
		out.Raw = res.Raw
		out.HasContent = res.Document != nil
		if res.Document != nil {
			out.ReturnedID = res.Document.ID().String()
			out.ContentKind = "document"
			out.Snapshot, _ = json.Marshal(map[string]string{"id": out.ReturnedID})
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
			out.Snapshot, _ = json.Marshal(map[string]string{"id": out.ReturnedID})
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
	out.HasContent = c != nil
	switch v := c.(type) {
	case *document.Document:
		out.ReturnedID = v.ID().String()
		out.ContentKind = "document"
		out.Snapshot, _ = json.Marshal(map[string]string{"id": out.ReturnedID})
	case vm.Method:
		out.ReturnedID = v.ID.String()
		out.ContentKind = "verification-method"
	}
	// Native typed content is archived as such, not advertised as a conformant
	// DID representation. The HTTP exchange preserves its actual wire encoding.
	var b []byte
	var err error
	switch v := c.(type) {
	case *document.Document:
		// This explicit ID snapshot does not claim to archive the complete data
		// model. Native documents have unexported fields and cannot be JSON-marshaled.
		b = out.Snapshot
	case vm.Method:
		b, err = json.Marshal(struct {
			vm.Method
			ID         string
			Controller string
		}{v, v.ID.String(), v.Controller.String()})
	default:
		b, err = json.Marshal(c)
	}
	if err != nil {
		return out, err
	}
	out.Raw = b
	return nativeResult(out, md, dm)
}
