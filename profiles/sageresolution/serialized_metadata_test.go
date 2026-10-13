package sageresolution

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

func metadataFixture() MetadataResult {
	return MetadataResult{Resolution: SerializedMetadata{Serializer: resolutionSerializer, Bytes: []byte(`{"contentType":"application/did","extra":{"list":["x",true,null,42,{}]}}`)}, Document: SerializedMetadata{Serializer: documentSerializer, Bytes: []byte(`{"versionId":"7","sage":{"time":1800000000}}`)}}
}
func TestMetadataPositiveAndIndependentFailures(t *testing.T) {
	for _, role := range []string{"resolution", "document"} {
		baseline := metadataFixture()
		for _, obs := range judgeMetadata(baseline, role, "unit-input") {
			if obs.Verdict != core.Pass || obs.Input != "unit-input" || !strings.Contains(obs.Observed, "serializer") {
				t.Fatal(obs)
			}
		}
		for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"x":[false,null,"",-9007199254740991,9007199254740991]}`)} {
			result := baseline
			if role == "resolution" {
				result.Resolution.Bytes = raw
			} else {
				result.Document.Bytes = raw
			}
			for _, obs := range judgeMetadata(result, role, "unit") {
				if obs.Verdict != core.Pass {
					t.Fatal(obs)
				}
			}
		}
		for _, raw := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(`"scalar"`), []byte(`{7:1}`), []byte(`{"x":undefined}`), []byte(`{"x":NaN}`), []byte(`{"x":1} {}`), []byte(`{"x":{"a":1,"a":2}}`), {0xff}} {
			result := baseline
			if role == "resolution" {
				result.Resolution.Bytes = raw
			} else {
				result.Document.Bytes = raw
			}
			for _, obs := range judgeMetadata(result, role, "unit") {
				if obs.Verdict != core.Fail || obs.Observed == "" {
					t.Fatal(raw, obs)
				}
			}
		}
		result := baseline
		if role == "resolution" {
			result.Resolution.Error = "native serializer failed"
			result.Resolution.Bytes = nil
		} else {
			result.Document.Error = "native serializer failed"
			result.Document.Bytes = nil
		}
		for i, obs := range judgeMetadata(result, role, "unit") {
			want := core.Error
			if i == 3 {
				want = core.Fail
			}
			if obs.Verdict != want || !strings.Contains(obs.Observed, "native serializer failed") {
				t.Fatal(obs)
			}
		}
		other := "document"
		if role == "document" {
			other = "resolution"
		}
		for _, obs := range judgeMetadata(result, other, "unit") {
			if obs.Verdict != core.Pass {
				t.Fatal("failure leaked to other metadata", obs)
			}
		}
		result = baseline
		if role == "resolution" {
			result.Resolution.Serializer = "generic json.Marshal"
		} else {
			result.Document.Serializer = ""
		}
		for _, obs := range judgeMetadata(result, role, "unit") {
			if obs.Verdict != core.Error {
				t.Fatal("unattributed pass", obs)
			}
		}
	}
}
func TestMetadataSerializabilityBoundary(t *testing.T) {
	for _, raw := range []string{`{"x":"한글"}`, `{"한글":null}`, `{"x":9007199254740992}`, `{"x":9007199254740991.1}`, `{"x":1e400}`, `{"x":[1.5]}`, `{"x":{"a":-9007199254740992}}`, `{"x":"\ud800"}`} {
		result := metadataFixture()
		result.Resolution.Bytes = []byte(raw)
		obs := judgeMetadata(result, "resolution", "unit")
		for i, o := range obs {
			want := core.Pass
			if i == 3 {
				want = core.NotSupported
			}
			if o.Verdict != want {
				t.Fatal(raw, o)
			}
		}
	}
}

// These mutations are unit-only negative controls, never subject outputs.
type metadataOnly struct{ fail bool }

func (metadataOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit-metadata"} }
func (metadataOnly) Supports(string, core.Capability) bool { return false }
func (s metadataOnly) InspectMetadata(context.Context, sageprojection.Record, Request) (MetadataResult, error) {
	if s.fail {
		return MetadataResult{}, errors.New("execution failure")
	}
	return metadataFixture(), nil
}
func TestMetadataCasesKeepOperationAndInput(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-1.1"}
	appendMetadataCases(&p, rows)
	if len(p.Cases) != 24 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, tc := range []struct {
			subject core.Subject
			want    core.Verdict
		}{{metadataOnly{}, core.Pass}, {metadataOnly{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, obs := range c.Run(t.Context(), tc.subject) {
				if obs.Verdict != tc.want || obs.Input == "" {
					t.Fatal(c.ID, obs)
				}
			}
		}
	}
	p = core.Profile{Name: "did-core-1.0"}
	appendMetadataCases(&p, rows)
	if len(p.Cases) != 0 {
		t.Fatal("legacy attribution")
	}
}
