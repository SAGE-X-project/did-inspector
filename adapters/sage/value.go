package sage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// The subject's validation result is retained as an actual call outcome, never
// an expected verdict or oracle. Fixed independent literal controls judge it.
func (*Subject) InspectLibraryValue(_ context.Context, q sageresolution.LibraryValueRequest) (sageresolution.LibraryValueResult, error) {
	out := sageresolution.LibraryValueResult{Request: q}
	var read, validate func() error
	var write func() ([]byte, error)
	switch q.Kind {
	case "document-metadata":
		id, e := did.Parse(q.Subject)
		if e != nil {
			return out, e
		}
		var m document.Metadata
		out.Reader = "github.com/sage-x-project/did-go/document.Metadata.UnmarshalJSON"
		read = func() error { return json.Unmarshal(q.Input, &m) }
		validate = func() error {
			out.Validator = "github.com/sage-x-project/did-go/document.Metadata.Check"
			return m.Check(id, spec.V11)
		}
		write = func() ([]byte, error) {
			out.Writer = "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON"
			return m.MarshalJSON()
		}
	case "resolution-metadata", "dereferencing-metadata":
		var m resolution.ResolutionMetadata
		out.Reader = "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.UnmarshalJSON"
		read = func() error { return json.Unmarshal(q.Input, &m) }
		validate = func() error {
			out.Validator = "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.Validate"
			return m.Validate(spec.V11)
		}
		write = func() ([]byte, error) {
			out.Writer = "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON"
			return m.MarshalJSON()
		}
	case "resolution-options":
		var o resolution.ResolutionOptions
		out.Reader = "github.com/sage-x-project/did-go/resolution.ResolutionOptions.UnmarshalJSON"
		read = func() error { return json.Unmarshal(q.Input, &o) }
		validate = func() error {
			out.Validator = "github.com/sage-x-project/did-go/resolution.ResolutionOptions.Validate"
			if e := o.Validate(); e != nil {
				return e
			}
			return nil
		}
		write = func() ([]byte, error) {
			out.Writer = "github.com/sage-x-project/did-go/resolution.ResolutionOptions.MarshalJSON"
			return o.MarshalJSON()
		}
	default:
		return out, errors.New("unknown typed library value operation")
	}
	if e := read(); e != nil {
		out.ReadError = e.Error()
		return out, nil
	}
	if e := validate(); e != nil {
		out.ValidationError = e.Error()
		return out, nil
	}
	b, e := write()
	out.Output = append([]byte(nil), b...)
	if e != nil {
		out.WriteError = e.Error()
	}
	return out, nil
}
