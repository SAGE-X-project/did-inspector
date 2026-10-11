package fixtures

import (
	"errors"
	"strings"
	"testing"
)

const sample = `{
  "format": "did-inspector-fixture-registry/1",
  "method": "example",
  "entries": {
    "did:example:a": {"versions": [
      {"versionId": "1", "validFrom": "2020-01-01T00:00:00Z", "mediaType": "application/did", "document": {"id": "did:example:a"}, "documentMetadata": {"versionId": "1"}},
      {"versionId": "2", "validFrom": "2021-01-01T00:00:00Z", "mediaType": "application/did", "document": {"id":"did:example:a","v":2}, "documentMetadata": {}}
    ]},
    "did:example:gone": {"deactivated": true, "versions": [
      {"versionId": "1", "validFrom": "2020-01-01T00:00:00Z", "mediaType": "application/did", "document": {"id": "did:example:gone"}, "documentMetadata": {}}
    ]},
    "did:example:bad": {"versions": [
      {"versionId": "1", "validFrom": "2020-01-01T00:00:00Z", "mediaType": "application/did", "text": "{not json", "documentMetadata": {}}
    ]},
    "did:example:fail": {"fail": "storage offline"}
  }
}`

func mustParse(t *testing.T) *Registry {
	t.Helper()
	r, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReadCurrentAndVersions(t *testing.T) {
	r := mustParse(t)
	if got := r.DIDs(); len(got) != 4 || got[0] != "did:example:a" {
		t.Fatalf("DIDs = %v", got)
	}
	cases := []struct {
		req     Request
		version string
		err     error
	}{
		{Request{DID: "did:example:a"}, "2", nil},
		{Request{DID: "did:example:a", VersionID: "1"}, "1", nil},
		{Request{DID: "did:example:a", VersionTime: "2020-06-01T00:00:00Z"}, "1", nil},
		{Request{DID: "did:example:a", VersionTime: "2021-01-01T00:00:00Z"}, "2", nil},
		{Request{DID: "did:example:a", VersionTime: "2021-06-01T00:00:00Z", VersionID: "2"}, "2", nil},
		{Request{DID: "did:example:a", VersionTime: "2021-06-01T00:00:00Z", VersionID: "1"}, "", ErrVersionNotFound},
		{Request{DID: "did:example:a", VersionTime: "2019-01-01T00:00:00Z"}, "", ErrVersionNotFound},
		{Request{DID: "did:example:a", VersionID: "9"}, "", ErrVersionNotFound},
		{Request{DID: "did:example:a", VersionTime: "2021-01-01T00:00:00.5Z"}, "", ErrInvalidVersionTime},
		{Request{DID: "did:example:nope"}, "", ErrNotFound},
		{Request{DID: "did:other:a"}, "", ErrMethodNotSupported},
	}
	for _, c := range cases {
		rec, err := r.Read(c.req)
		if !errors.Is(err, c.err) || rec.VersionID != c.version {
			t.Errorf("Read(%+v) = %q, %v; want %q, %v", c.req, rec.VersionID, err, c.version, c.err)
		}
	}
	rec, _ := r.Read(Request{DID: "did:example:a"})
	if string(rec.Bytes) != `{"id":"did:example:a","v":2}` || rec.MediaType != "application/did" || string(rec.Metadata) != "{}" || rec.Deactivated {
		t.Errorf("record = %+v", rec)
	}
}

func TestReadStates(t *testing.T) {
	r := mustParse(t)
	if rec, err := r.Read(Request{DID: "did:example:gone"}); err != nil || !rec.Deactivated {
		t.Errorf("deactivated = %+v, %v", rec, err)
	}
	if rec, err := r.Read(Request{DID: "did:example:bad"}); err != nil || string(rec.Bytes) != "{not json" {
		t.Errorf("text = %+v, %v", rec, err)
	}
	_, err := r.Read(Request{DID: "did:example:fail"})
	var inj *InjectedError
	if !errors.As(err, &inj) || inj.Message != "storage offline" || !strings.Contains(err.Error(), "did:example:fail") {
		t.Errorf("fail = %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	version := func(extra string) string {
		return `{"format":"did-inspector-fixture-registry/1","method":"example","entries":{"did:example:x":{"versions":[{` + extra + `}]}}}`
	}
	ok := `"versionId":"1","validFrom":"2020-01-01T00:00:00Z","mediaType":"m","document":{},"documentMetadata":{}`
	if _, err := Parse([]byte(version(ok))); err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}
	bad := map[string]string{
		"syntax":         `{`,
		"trailing":       version(ok) + `{}`,
		"unknown field":  version(ok + `,"x":1`),
		"format":         `{"format":"x","method":"example","entries":{}}`,
		"method":         `{"format":"did-inspector-fixture-registry/1","method":"web","entries":{}}`,
		"foreign did":    `{"format":"did-inspector-fixture-registry/1","method":"example","entries":{"did:web:x":{"fail":"f"}}}`,
		"bare prefix":    `{"format":"did-inspector-fixture-registry/1","method":"example","entries":{"did:example:":{"fail":"f"}}}`,
		"empty entry":    `{"format":"did-inspector-fixture-registry/1","method":"example","entries":{"did:example:x":{}}}`,
		"no version id":  version(`"validFrom":"2020-01-01T00:00:00Z","mediaType":"m","document":{},"documentMetadata":{}`),
		"bad time":       version(`"versionId":"1","validFrom":"2020","mediaType":"m","document":{},"documentMetadata":{}`),
		"no media type":  version(`"versionId":"1","validFrom":"2020-01-01T00:00:00Z","document":{},"documentMetadata":{}`),
		"no document":    version(`"versionId":"1","validFrom":"2020-01-01T00:00:00Z","mediaType":"m","documentMetadata":{}`),
		"both":           version(ok + `,"text":"x"`),
		"array metadata": version(`"versionId":"1","validFrom":"2020-01-01T00:00:00Z","mediaType":"m","document":{},"documentMetadata":[]`),
		"order": `{"format":"did-inspector-fixture-registry/1","method":"example","entries":{"did:example:x":{"versions":[{` + ok + `},{` +
			strings.Replace(ok, `"1"`, `"2"`, 1) + `}]}}}`,
	}
	for name, data := range bad {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
