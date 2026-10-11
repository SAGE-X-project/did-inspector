package didgo

import (
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// testRegistry is a small fixture registry for the adapter's own tests.
const testRegistry = `{
  "format": "did-inspector-fixture-registry/1",
  "method": "example",
  "entries": {
    "did:example:a": {"versions": [
      {"versionId": "1", "validFrom": "2021-01-01T00:00:00Z", "mediaType": "application/did",
       "document": {"@context": "https://www.w3.org/ns/did/v1.1", "id": "did:example:a"},
       "documentMetadata": {"created": "2021-01-01T00:00:00Z", "versionId": "1"}},
      {"versionId": "2", "validFrom": "2021-02-01T00:00:00Z", "mediaType": "application/did",
       "document": {"@context": "https://www.w3.org/ns/did/v1.1", "id": "did:example:a",
         "verificationMethod": [{"id": "#key-1", "type": "Multikey", "controller": "did:example:a",
           "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"}],
         "service": [{"id": "#files", "type": "FileService", "serviceEndpoint": "https://example.com/files/"}]},
       "documentMetadata": {"created": "2021-01-01T00:00:00Z", "updated": "2021-02-01T00:00:00Z", "versionId": "2"}}
    ]},
    "did:example:v10": {"versions": [
      {"versionId": "1", "validFrom": "2021-01-01T00:00:00Z", "mediaType": "application/did+json",
       "document": {"id": "did:example:v10", "verificationMethod": [{"id": "did:example:v10#key-1",
         "type": "JsonWebKey2020", "controller": "did:example:v10",
         "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}}]},
       "documentMetadata": {"created": "2021-01-01T00:00:00Z"}}
    ]},
    "did:example:gone": {"deactivated": true, "versions": [
      {"versionId": "1", "validFrom": "2021-01-01T00:00:00Z", "mediaType": "application/did",
       "document": {"id": "did:example:gone"}, "documentMetadata": {"created": "2021-01-01T00:00:00Z"}}
    ]},
    "did:example:badmeta": {"versions": [
      {"versionId": "1", "validFrom": "2021-01-01T00:00:00Z", "mediaType": "application/did",
       "document": {"id": "did:example:badmeta"}, "documentMetadata": {"created": "yesterday"}}
    ]},
    "did:example:broken": {"fail": "registry unreachable"}
  }
}`

func registry(t *testing.T) *fixtures.Registry {
	t.Helper()
	r, err := fixtures.Parse([]byte(testRegistry))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func loaded(t *testing.T) *Subject {
	t.Helper()
	s := New()
	if err := s.LoadFixtureRegistry(registry(t)); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustDoc(t *testing.T, s string) core.DocumentJSON {
	t.Helper()
	d, err := core.ParseDocumentJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func compact(t *testing.T, v interface{ MarshalJSON() ([]byte, error) }) string {
	t.Helper()
	b, err := v.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func str(d core.DocumentJSON, name string) string {
	v, _ := d.Get(name)
	return v.Str
}

func errorType(d core.DocumentJSON) string {
	v, ok := d.Get("error")
	if !ok {
		return ""
	}
	if v.Kind == core.KindString {
		return v.Str
	}
	t, _ := v.Get("type")
	return t.Str
}
