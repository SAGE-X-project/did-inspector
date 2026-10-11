package kit

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// Functions a scenario can call.
const (
	FnResolve                 = "resolve"
	FnDereference             = "dereference"
	FnResolve10               = "resolve10"
	FnResolveRepresentation10 = "resolveRepresentation10"
	FnDereference10           = "dereference10"
)

// FunctionCapability returns the capability that provides a function.
func FunctionCapability(fn string) (core.Capability, bool) {
	switch fn {
	case FnResolve:
		return core.CapResolver, true
	case FnDereference:
		return core.CapDereferencer, true
	case FnResolve10, FnResolveRepresentation10, FnDereference10:
		return core.CapV10Functions, true
	}
	return "", false
}

// Outcome is the result of one resolution or dereferencing call in a form
// common to all functions.
type Outcome struct {
	Function string
	Input    string
	// Metadata is the DID resolution metadata or the DID URL dereferencing
	// metadata.
	Metadata core.DocumentJSON
	// Document is the DID document in its abstract form (resolve).
	Document *core.DocumentJSON
	// Stream is the didDocumentStream or contentStream and MediaType the
	// media type the subject declared for it.
	Stream    []byte
	MediaType string
	// ContentMetadata is the DID document metadata or the content metadata.
	ContentMetadata core.DocumentJSON
	// Err is the Go error the call returned instead of a result.
	Err error
}

// Call invokes a function of the subject. The subject must implement the
// function's capability.
func Call(ctx context.Context, s core.Subject, fn, input string, opts map[string]any) Outcome {
	o := Outcome{Function: fn, Input: input}
	var rr core.ResolutionResult
	var dr core.DereferenceResult
	isDeref := false
	switch fn {
	case FnResolve:
		rr, o.Err = s.(core.Resolver).Resolve(ctx, input, opts)
	case FnResolve10:
		rr, o.Err = s.(core.V10Functions).Resolve10(ctx, input, opts)
	case FnResolveRepresentation10:
		rr, o.Err = s.(core.V10Functions).ResolveRepresentation10(ctx, input, opts)
	case FnDereference:
		dr, o.Err = s.(core.Dereferencer).Dereference(ctx, input, opts)
		isDeref = true
	case FnDereference10:
		dr, o.Err = s.(core.V10Functions).Dereference10(ctx, input, opts)
		isDeref = true
	default:
		o.Err = fmt.Errorf("kit: unknown function %q", fn)
	}
	if isDeref {
		o.Metadata, o.Stream, o.MediaType, o.ContentMetadata = dr.DereferencingMetadata, dr.Content, dr.MediaType, dr.ContentMetadata
	} else {
		o.Metadata, o.Document, o.Stream, o.MediaType, o.ContentMetadata = rr.ResolutionMetadata, rr.Document, rr.Raw, rr.MediaType, rr.DocumentMetadata
	}
	return o
}

// ErrorValue returns the error property of the metadata.
func (o Outcome) ErrorValue() (core.Value, bool) {
	return o.Metadata.Get("error")
}

// Failed reports whether the metadata carries an error property.
func (o Outcome) Failed() bool {
	_, ok := o.ErrorValue()
	return ok
}

// ErrorCode returns the error as the subject reported it: the type of an
// error object, or the string of an error keyword (DID Core 1.0). It
// returns "" when there is no error or it has neither form.
func (o Outcome) ErrorCode() string {
	v, ok := o.ErrorValue()
	switch {
	case !ok:
		return ""
	case v.Kind == core.KindString:
		return v.Str
	case v.Kind == core.KindObject:
		if t, ok := v.Get("type"); ok && t.Kind == core.KindString {
			return t.Str
		}
	}
	return ""
}

// HasContent reports whether the call returned a document or a stream.
func (o Outcome) HasContent() bool {
	return o.Document != nil || len(o.Stream) > 0
}

// Succeeded reports whether the call returned content and no error.
func (o Outcome) Succeeded() bool {
	return o.Err == nil && !o.Failed() && o.HasContent()
}

// Doc returns the returned resource as a JSON object: the abstract
// document, or the stream parsed as JSON. The string explains a failure.
func (o Outcome) Doc() (core.DocumentJSON, string) {
	if o.Document != nil {
		return *o.Document, ""
	}
	if len(o.Stream) == 0 {
		return core.DocumentJSON{}, "no document or content"
	}
	d, err := core.ParseDocumentJSON(o.Stream)
	if err != nil {
		return core.DocumentJSON{}, "content is not a JSON object: " + err.Error()
	}
	return d, ""
}

// StringMember returns a string member of a metadata structure.
func StringMember(d core.DocumentJSON, name string) (string, bool) {
	v, ok := d.Get(name)
	if !ok || v.Kind != core.KindString {
		return "", false
	}
	return v.Str, true
}

// Summary describes an outcome for an observation's observed value.
func (o Outcome) Summary() string {
	if o.Err != nil {
		return "call failed: " + o.Err.Error()
	}
	s := "metadata " + checks.Compact(o.Metadata.Value())
	if o.Document != nil {
		s += ", document " + checks.Compact(o.Document.Value())
	}
	if len(o.Stream) > 0 {
		s += fmt.Sprintf(", stream %q (%s)", clip(o.Stream), o.MediaType)
	}
	return s + ", content metadata " + checks.Compact(o.ContentMetadata.Value())
}

func clip(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
