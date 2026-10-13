package sage

import (
	"bytes"
	"testing"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func TestDirectMetadataCallsPreserveActualBytes(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	for _, q := range []sageresolution.Request{{Function: "resolve", Input: rows[0].DID, Accept: "application/did"}, {Function: "resolve", Input: "not-a-did"}, {Function: "resolve", Input: rows[0].DID, SourceFailure: "record.stale"}, {Function: "dereference", Input: rows[0].DID + "#sign", Accept: "application/did"}, {Function: "dereference", Input: rows[0].DID + "#missing", Accept: "application/did"}} {
		result, err := s.InspectMetadata(t.Context(), rows[0], q)
		if err != nil || result.Resolution.Error != "" || result.Document.Error != "" {
			t.Fatal(q, result, err)
		}
		native, err := s.InspectResolution(t.Context(), rows[0], q)
		if err != nil || !bytes.Equal(native.Metadata, result.Resolution.Bytes) || !bytes.Equal(native.ContentMetadata, result.Document.Bytes) || native.SageCode != result.SageCode {
			t.Fatal("repaired or mismatched output", q, err)
		}
	}
	bad := rows[0]
	bad.DID = "bad"
	if _, err := s.InspectMetadata(t.Context(), bad, sageresolution.Request{Function: "resolve"}); err == nil {
		t.Fatal("bad fixture")
	}
	for _, q := range []sageresolution.Request{{Function: "http"}, {Function: "resolve10"}, {Function: "resolve", NativeFunction: "resolve"}, {Function: "resolve", HTTP: &core.HTTPRequest{}}, {Function: "dereference", Input: "bad"}} {
		if _, err := s.InspectMetadata(t.Context(), rows[0], q); err == nil {
			t.Fatal(q)
		}
	}
}
func TestMetadataSerializerErrorsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		md                             resolution.ResolutionMetadata
		dm                             document.Metadata
		resolutionError, documentError bool
	}{{resolution.ResolutionMetadata{Extra: map[string]any{"bad": func() {}}}, document.Metadata{}, true, false}, {resolution.ResolutionMetadata{}, document.Metadata{Extra: map[string]any{"bad": func() {}}}, false, true}, {resolution.ResolutionMetadata{}, document.Metadata{}, false, false}} {
		result := serializeMetadata(tc.md, tc.dm)
		if (result.Resolution.Error != "") != tc.resolutionError || (result.Document.Error != "") != tc.documentError {
			t.Fatal(result)
		}
		if result.Resolution.Serializer != "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON" || result.Document.Serializer != "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON" {
			t.Fatal(result)
		}
	}
}
