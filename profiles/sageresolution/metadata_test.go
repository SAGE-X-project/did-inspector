package sageresolution

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func TestMetadataFieldsUseIndependentFormatRules(t *testing.T) {
	for _, tc := range []struct {
		check, field, good string
		bad                []string
		legacy             bool
	}{
		{"version-ascii", "versionId", `"7"`, []string{`7`, `null`, `"é"`}, false},
		{"content-type-ascii", "contentType", `"application/did; profile=example"`, []string{`7`, `null`, `"application/did; x=é"`}, false},
		{"legacy-keyword", "error", `"notFound"`, []string{`"not found"`, `"é"`, `null`, `7`}, true},
		{"prefixed-error", "error", `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`, []string{`{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}`, `{"type":"https://example.org/NOT_FOUND"}`, `{"type":7}`, `7`}, false},
	} {
		id := "res10-crd20261001#errors.3"
		if tc.legacy {
			id = "core10#did-resolution-metadata.6"
		}
		w := expected{Check: tc.check, Value: "NOT_FOUND", Statements: []string{id}}
		for i, value := range append([]string{tc.good}, tc.bad...) {
			r := native()
			raw := json.RawMessage(`{"` + tc.field + `":` + value + `}`)
			if tc.field == "versionId" {
				r.ContentMetadata = raw
			} else {
				r.Metadata = raw
			}
			obs := judge(r, []expected{w}, "original-input")
			if (obs[0].Verdict == core.Pass) != (i == 0) {
				t.Fatal(tc.check, value, obs)
			}
			if obs[0].Input != "original-input" || !strings.Contains(obs[0].Observed, tc.field) {
				t.Fatal("lost raw evidence", obs)
			}
		}
		r := Result{Metadata: json.RawMessage(`{}`), ContentMetadata: json.RawMessage(`{}`)}
		want := core.NotApplicable
		if obs := judge(r, []expected{w}, ""); obs[0].Verdict != want {
			t.Fatal("omission", tc.check, obs)
		}
	}
	md, _ := parse([]byte(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`))
	for _, value := range []any{nil, "not a keyword"} {
		if _, err := checkMetadata(Result{}, md, core.DocumentJSON{}, expected{Check: "prefixed-error", Value: value}); err == nil {
			t.Fatal("invalid case expectation")
		}
	}
	md, _ = parse([]byte(`{"contentType":"application/did"}`))
	if _, err := checkMetadata(Result{}, md, core.DocumentJSON{}, expected{Check: "unknown"}); err == nil {
		t.Fatal("unknown check")
	}
}

func TestHTTPMetadataComesFromTheActualEnvelope(t *testing.T) {
	for _, deref := range []bool{false, true} {
		mt, body := "application/did-resolution", `{"didDocument":{"id":"did:sage:web:x:a"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{"versionId":"7"}}`
		if deref {
			mt, body = "application/did-url-dereferencing", `{"content":{"id":"did:sage:web:x:a"},"dereferencingMetadata":{"contentType":"application/json"},"contentMetadata":{"versionId":"7"}}`
		}
		ex := core.HTTPExchange{Status: 200, Header: http.Header{"Content-Type": {mt}}, Body: []byte(body)}
		// Conflicting translated fields must not replace the actual wire values.
		r := Result{Exchange: &ex, Metadata: json.RawMessage(`{"contentType":7}`), ContentMetadata: json.RawMessage(`{"versionId":7}`)}
		for _, name := range []string{"content-type-ascii", "version-ascii"} {
			w := expected{Check: name, Statements: []string{"s"}}
			if obs := judge(r, []expected{w}, ""); obs[0].Verdict != core.Pass {
				t.Fatal(name, obs)
			}
		}
		for _, corrupt := range []string{`{`, strings.Replace(body, `"versionId":"7"`, `"versionId":"7","versionId":"8"`, 1), `{"didResolutionMetadata":null,"didDocumentMetadata":{}}`} {
			ex.Body = []byte(corrupt)
			if obs := judge(r, []expected{{Check: "version-ascii", Statements: []string{"s"}}}, ""); obs[0].Verdict != core.Error {
				t.Fatal("unreadable envelope", obs)
			}
		}
		ex.Header.Set("Content-Type", "application/did")
		ex.Body = []byte(`{}`)
		if obs := judge(r, []expected{{Check: "version-ascii", Statements: []string{"s"}}}, ""); obs[0].Verdict != core.Error {
			t.Fatal("not an envelope", obs)
		}
	}
}

func TestVersionFormatDoesNotRequireOneFixtureValue(t *testing.T) {
	for _, version := range []string{"", "8", "historical-version", "v2"} {
		r := native()
		r.ContentMetadata, _ = json.Marshal(map[string]string{"versionId": version})
		if obs := judge(r, []expected{{Check: "version-ascii", Statements: []string{"s"}}}, ""); obs[0].Verdict != core.Pass {
			t.Fatal(version, obs)
		}
	}
}

func TestStandardPrefixChecksDoNotApplyToExtensionErrors(t *testing.T) {
	// The extension case retains its own observation, never errors.3.
	p, err := Profile("did-1.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Cases {
		if strings.HasSuffix(c.ID, "/unauthorized-key") {
			for _, id := range c.Statements {
				if id == "res10-crd20261001#errors.3" {
					t.Fatal("extension incorrectly requires standard prefix")
				}
			}
		}
	}
}

func TestMediaTypeMatchesActualFixtureRepresentation(t *testing.T) {
	for _, mt := range []string{"application/did", "application/did+json"} {
		r := native()
		r.Metadata, _ = json.Marshal(map[string]string{"contentType": mt})
		r.Raw = []byte(`{"id":"did:sage:web:x:a","@context":"https://www.w3.org/ns/did/v1.1"}`)
		w := expected{Check: "resolution-media-type", Value: mt, Statements: []string{"s"}}
		if obs := judge(r, []expected{w}, ""); obs[0].Verdict != core.Pass {
			t.Fatal("correct representation", obs)
		}
		for _, wrong := range []string{`{"contentType":"text/html"}`, `{"contentType":7}`} {
			bad := r
			bad.Metadata = json.RawMessage(wrong)
			if obs := judge(bad, []expected{w}, ""); obs[0].Verdict != core.Fail {
				t.Fatal("wrong media label", obs)
			}
		}
		for _, malformed := range []string{`{`, `{"id":7}`, `{"id":"did:sage:web:x:a"}`} {
			if mt == "application/did+json" && strings.Contains(malformed, `"id":"`) {
				continue
			}
			bad := r
			bad.Raw = []byte(malformed)
			if obs := judge(bad, []expected{w}, ""); obs[0].Verdict != core.Fail {
				t.Fatal("wrong content", obs)
			}
		}
		bad := r
		bad.HasContent = false
		if obs := judge(bad, []expected{w}, ""); obs[0].Verdict != core.Fail {
			t.Fatal("missing native content", obs)
		}
		for _, expectation := range []any{nil, "text/html"} {
			w.Value = expectation
			if obs := judge(r, []expected{w}, ""); obs[0].Verdict != core.Error {
				t.Fatal("invalid media expectation", obs)
			}
		}
	}
}

func TestDereferencingMediaRecommendationChecksReturnedWireContent(t *testing.T) {
	w := expected{Check: "dereference-media-type", Value: "application/json", Statements: []string{"s"}}
	ex := core.HTTPExchange{Status: 200, Header: http.Header{"Content-Type": {"application/did-url-dereferencing"}}}
	for _, tc := range []struct {
		body    string
		verdict core.Verdict
	}{
		{`{"content":{"id":"did:sage:web:x:a#sign"},"dereferencingMetadata":{"contentType":"application/json"},"contentMetadata":{}}`, core.Pass},
		{`{"content":{"id":"did:sage:web:x:a#sign"},"dereferencingMetadata":{"contentType":"text/html"},"contentMetadata":{}}`, core.Fail},
		{`{"content":{"id":"did:sage:web:x:a#sign"},"dereferencingMetadata":{},"contentMetadata":{}}`, core.Fail},
		{`{"content":{"id":7},"dereferencingMetadata":{"contentType":"application/json"},"contentMetadata":{}}`, core.Fail},
		{`{"content":null,"dereferencingMetadata":{"contentType":"application/json"},"contentMetadata":{}}`, core.NotApplicable},
		{`{"content":{"id":"did:sage:web:x:a#sign"},"dereferencingMetadata":{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"},"contentType":"application/json"},"contentMetadata":{}}`, core.NotApplicable},
	} {
		ex.Body = []byte(tc.body)
		if obs := judge(Result{Exchange: &ex}, []expected{w}, ""); obs[0].Verdict != tc.verdict {
			t.Fatal(tc.body, obs)
		}
	}
	r := native()
	r.Metadata = json.RawMessage(`{"contentType":"application/json"}`)
	if obs := judge(r, []expected{w}, ""); obs[0].Verdict != core.Error {
		t.Fatal("native snapshot advertised as wire", obs)
	}
}

func TestEquivalentMediaTypesAndContextArraysAreAccepted(t *testing.T) {
	for _, mt := range []string{"Application/DID", "application/did; profile=example"} {
		for _, ctx := range []string{`"https://www.w3.org/ns/did/v1.1"`, `["https://www.w3.org/ns/did/v1.1"]`, `["https://www.w3.org/ns/did/v1.1", "https://example.org/context"]`} {
			r := native()
			r.Metadata, _ = json.Marshal(map[string]string{"contentType": mt})
			r.Raw = []byte(`{"id":"did:sage:web:x:a","@context":` + ctx + `}`)
			w := expected{Check: "resolution-media-type", Value: "application/did", Statements: []string{"s"}}
			if obs := judge(r, []expected{w}, ""); obs[0].Verdict != core.Pass {
				t.Fatal(mt, ctx, obs)
			}
		}
	}
	for _, ctx := range []string{`[]`, `[7]`, `["https://example.org/context", "https://www.w3.org/ns/did/v1.1"]`, `7`} {
		r := native()
		r.Metadata = json.RawMessage(`{"contentType":"application/did"}`)
		r.Raw = []byte(`{"id":"did:sage:web:x:a","@context":` + ctx + `}`)
		if obs := judge(r, []expected{{Check: "resolution-media-type", Value: "application/did", Statements: []string{"s"}}}, ""); obs[0].Verdict != core.Fail {
			t.Fatal(ctx, obs)
		}
	}
	ex := core.HTTPExchange{Header: http.Header{"Content-Type": {"application/did-url-dereferencing"}}, Body: []byte(`{"content":{},"dereferencingMetadata":{"error":{},"contentType":"application/json"},"contentMetadata":{}}`)}
	if obs := judge(Result{Exchange: &ex}, []expected{{Check: "dereference-media-type", Value: "application/json", Statements: []string{"s"}}}, ""); obs[0].Verdict != core.Error {
		t.Fatal("malformed wire error", obs)
	}
}
