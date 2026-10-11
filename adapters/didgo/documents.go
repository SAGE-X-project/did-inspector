package didgo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
)

// version translates the inspector's DID version string ("1.0", "1.1",
// or "" for none) to did-go's.
func version(s string) (spec.Version, error) {
	if s == "" {
		return spec.VUnknown, nil
	}
	return spec.ParseVersion(s)
}

// Consume consumes data with did-go's consumer. requireVersion becomes
// ConsumeOptions.Require and, for low-precision input without @context,
// ConsumeOptions.Expected; strict becomes ConsumeOptions.Strict. The
// returned document holds the data model entries; the representation-
// specific entries are in the ConsumeInfo.
func (s *Subject) Consume(data []byte, mediaType, requireVersion string, strict bool) (core.DocumentJSON, core.ConsumeInfo, error) {
	v, err := version(requireVersion)
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, err
	}
	doc, info, err := s.consumer.Consume(data, mediaType, representation.ConsumeOptions{Expected: v, Require: v, Strict: strict})
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, err
	}
	out, err := documentJSON(doc)
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, fmt.Errorf("didgo adapter: translating the consumed document: %w", err)
	}
	entries, err := representationEntries(doc)
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, fmt.Errorf("didgo adapter: translating the representation-specific entries: %w", err)
	}
	return out, core.ConsumeInfo{
		MediaType:             representation.MediaTypeOf(info),
		Version:               info.DetectedVersion.String(),
		RepresentationEntries: entries,
		Notes:                 consumeNotes(info),
	}, nil
}

func consumeNotes(info representation.ConsumeInfo) []string {
	var notes []string
	if info.Assumed {
		notes = append(notes, "version assumed without @context")
	}
	if info.LowPrecision != nil {
		notes = append(notes, fmt.Sprintf("low-precision media type %s decided as %s", info.LowPrecision.Declared, info.LowPrecision.Detected))
	}
	if info.UnexpectedContext != "" {
		notes = append(notes, "unexpected @context "+info.UnexpectedContext)
	}
	for _, t := range info.DroppedTerms {
		notes = append(notes, "dropped term "+t)
	}
	return notes
}

// translator reads the inspector's JSON form of a document into did-go's
// data model. did-go's only public way from JSON to a Document is its
// consumer, so the adapter uses it, configured to keep every entry
// (KeepUndefinedTerms) and without strict detection, with the media type
// of the target version's representation.
var translator = consumer.New(consumer.KeepUndefinedTerms())

// toDocument reads doc into did-go's data model for version v. A document
// did-go cannot hold is an error.
func toDocument(doc core.DocumentJSON, v spec.Version) (*document.Document, error) {
	data, err := doc.MarshalJSON()
	if err != nil {
		return nil, err
	}
	d, _, err := translator.Consume(data, mediaTypeFor(doc, v), representation.ConsumeOptions{Require: v})
	return d, err
}

func hasContext(doc core.DocumentJSON) bool {
	_, ok := doc.Get("@context")
	return ok
}

// mediaTypeFor returns the media type of the representation of doc under
// version v: application/did for DID 1.1, and for DID Core 1.0 the JSON-LD
// representation when doc has @context and the JSON one otherwise.
func mediaTypeFor(doc core.DocumentJSON, v spec.Version) string {
	return representation.MediaTypeFor(v, v == spec.V10 && hasContext(doc))
}

// Produce serializes doc with did-go's producer for the version, writing
// the JSON-LD representation (ProduceOptions.JSONLD) when doc has
// @context. A document that did-go cannot read into its data model is
// refused like one the producer refuses.
func (s *Subject) Produce(doc core.DocumentJSON, ver string) ([]byte, string, error) {
	v, err := version(ver)
	if err != nil {
		return nil, "", err
	}
	if v == spec.VUnknown {
		v = spec.Latest
	}
	d, err := toDocument(doc, v)
	if err != nil {
		return nil, "", fmt.Errorf("did-go cannot hold the document: %w", err)
	}
	return s.producer.Produce(d, representation.ProduceOptions{Version: v, JSONLD: hasContext(doc)})
}

// Validate reads doc into did-go's data model and runs document.Validate
// for the version. It reports the findings of severity error, which mark
// a violated MUST; warnings about recommendations are not problems of
// conformance and are left out. A document did-go cannot read into its
// data model is reported as one finding with did-go's reason.
func (s *Subject) Validate(doc core.DocumentJSON, ver string) ([]core.Finding, error) {
	v, err := version(ver)
	if err != nil {
		return nil, err
	}
	if v == spec.VUnknown {
		v = spec.Latest
	}
	d, err := toDocument(doc, v)
	if err != nil {
		return []core.Finding{errorFinding(err)}, nil
	}
	var out []core.Finding
	for _, f := range document.Validate(d, v) {
		if f.Severity != document.SeverityError {
			continue
		}
		out = append(out, core.Finding{Code: codeOr(f.Statement, "did-go"), Path: pointer(f.Property), Message: f.Message})
	}
	return out, nil
}

// errorFinding translates the error with which did-go refused to read a
// document.
func errorFinding(err error) core.Finding {
	var ce *document.ConformanceError
	var cons *consumer.Error
	var de *representation.DetectError
	switch {
	case errors.As(err, &ce):
		return core.Finding{Code: codeOr(ce.Statement, string(ce.Code)), Path: pointer(ce.Property), Message: err.Error()}
	case errors.As(err, &cons):
		return core.Finding{Code: codeOr(cons.Statement, "consumer"), Path: pointer(cons.Property), Message: err.Error()}
	case errors.As(err, &de):
		return core.Finding{Code: "detect-step-" + strconv.Itoa(de.Step), Path: "", Message: err.Error()}
	}
	return core.Finding{Code: "did-go", Message: err.Error()}
}

func codeOr(code, fallback string) string {
	if code != "" {
		return code
	}
	return fallback
}

// pointer turns a did-go property path such as "service[0].id" into a
// JSON Pointer ("/service/0/id"). An empty path is the whole document.
func pointer(property string) string {
	if property == "" {
		return ""
	}
	var b strings.Builder
	for _, part := range strings.Split(property, ".") {
		name, rest, _ := strings.Cut(part, "[")
		if name != "" {
			b.WriteString("/" + escape(name))
		}
		for rest != "" {
			idx, after, _ := strings.Cut(rest, "]")
			b.WriteString("/" + escape(idx))
			_, rest, _ = strings.Cut(after, "[")
		}
	}
	return b.String()
}

func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
