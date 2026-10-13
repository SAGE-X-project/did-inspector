package sageresolution

import (
	"encoding/json"
	"strings"
	"testing"

	whatwg "github.com/nlnwa/whatwg-url/url"
	"github.com/sage-x-project/did-inspector/core"
)

func urlString(s string) core.Value { return core.Value{Kind: core.KindString, Str: s} }
func TestSelectedURLsAndStandardValidationErrors(t *testing.T) {
	// Explicit expectations come from URL Standard writing/parsing rules. These
	// harmless syntax controls never connect to the example domains.
	for _, s := range []string{"did:sage:web:registry.example:agent-1", "did:sage:web:x:a#sign", "did:example:123?key=one#frag", "did:example:a%20b", "https://example.org/a2a", "HTTPS://EXAMPLE.ORG:443/a?x=1#f", "https://example.org:8443/a%20b", "https://example.org/a/../b", "https://" + strings.Repeat("a", 63) + ".example/", "https://" + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61) + "/"} {
		if got := nativeURLValue(urlString(s)); got != core.Pass {
			t.Fatal(s, got)
		}
	}
	for _, s := range []string{"", " https://example.org/ ", "https:example.org", "https://example.org/>", "https://example.org/%s", "https://example.org\\path", "https://example.org:70000", "https://example.org:7z", "https://#fragment", "https://user@example.org/", "did:example:123%", "did:example:a>b", "did:example:12\n34", "https://example.org/a b", "https://-example.org/", "https://example-.org/", "https://ab--cd.example/", "https://a_b.example/", "https://example..org/", "https://" + strings.Repeat("a", 64) + ".example/", "https://" + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62) + "/"} {
		if got := nativeURLValue(urlString(s)); got != core.Fail {
			t.Fatal(s, got)
		}
	}
	for _, s := range []string{"#key", "/relative", "other:example", "http://example.org/", "did://host/a", "https://é.example/", "https://xn--9ca.example/", "https://exam%70le.org/", "https://[::1]/", "https://127.0.0.1/"} {
		if got := nativeURLValue(urlString(s)); got != core.NotSupported {
			t.Fatal(s, got)
		}
	}
	for _, v := range []core.Value{{}, {Kind: core.KindNumber}, {Kind: core.KindArray}} {
		if nativeURLValue(v) != core.Fail {
			t.Fatal(v)
		}
	}
	// A permissive WHATWG parser succeeds despite these validation errors.
	for _, s := range []string{"https:example.org", " https://example.org/ ", "https://example.org/%s", "did:example:12\n34"} {
		permissive, err := whatwg.Parse(s)
		if err != nil || permissive == nil {
			t.Fatal("control requires recoverable parse", s, err)
		}
		if nativeURLValue(urlString(s)) != core.Fail {
			t.Fatal("successful parsing alone is insufficient", s)
		}
	}
}
func urlDoc(snapshot string) Result {
	r := nativeSchemaFixture("did-1.1")
	r.Snapshot = json.RawMessage(snapshot)
	return r
}
func TestURLClausesInspectSeparateActualFields(t *testing.T) {
	r := nativeSchemaFixture("did-1.1")
	obs := judgeNativeURLs(r, "original")
	for _, o := range obs {
		want := core.Pass
		if o.Statement == "cid10#controllers.3" {
			want = core.NotApplicable
		}
		if o.Verdict != want || o.Input != "original" || !strings.Contains(o.Observed, "snapshot") {
			t.Fatal(o)
		}
	}
	for _, tc := range []struct{ old, new, id string }{
		{`"id":"did:sage:web:x:a"`, `"id":7`, "subjects.1"},
		{`"id":"did:sage:web:x:a#sign"`, `"id":"did:example:a>b"`, "verification-methods.5"},
		{`"controller":"did:sage:web:x:a"`, `"controller":" https://example.org/ "`, "verification-methods.7"},
		{`"id":"did:sage:web:x:a#a2a"`, `"id":"https:example.org"`, "services.6"},
		{`"serviceEndpoint":"https://example.org/a2a"`, `"serviceEndpoint":"https://example.org/%s"`, "services.13"},
	} {
		bad := r
		bad.Snapshot = json.RawMessage(strings.Replace(string(r.Snapshot), tc.old, tc.new, 1))
		got := judgeNativeURLs(bad, "")
		if nativeVerdict(got, tc.id) != core.Fail {
			t.Fatal(tc, got)
		}
		if tc.id == "services.13" && nativeVerdict(got, "core-properties.1") != core.Fail {
			t.Fatal("DID restriction not checked")
		}
	}
	for _, key := range []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"} {
		r = urlDoc(`{"id":"did:example:123","` + key + `":[{"id":"did:example:123#k","controller":"did:example:123","type":"IndependentExtension"}]}`)
		if nativeVerdict(judgeNativeURLs(r, ""), "verification-methods.5") != core.Pass {
			t.Fatal(key)
		}
		r.Snapshot = json.RawMessage(strings.Replace(string(r.Snapshot), `"controller":"did:example:123"`, `"controller":false`, 1))
		if nativeVerdict(judgeNativeURLs(r, ""), "verification-methods.7") != core.Fail {
			t.Fatal(key)
		}
	}
}
func TestOptionalControllerSetAndEndpointMapBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  core.Verdict
	}{
		{`"did:example:123"`, core.Pass}, {`["did:example:123","https://example.org/"]`, core.Pass},
		{`["did:example:123",7]`, core.Fail}, {`["did:example:123","did:example:123"]`, core.Fail},
		{`["https:example.org"]`, core.Fail}, {`null`, core.Fail}, {`[]`, core.NotApplicable},
	} {
		r := urlDoc(`{"id":"did:example:123","controller":` + tc.value + `}`)
		if got := nativeVerdict(judgeNativeURLs(r, ""), "controllers.3"); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	for _, tc := range []struct {
		value string
		want  core.Verdict
	}{
		{`"https://example.org/"`, core.Pass}, {`["https://example.org/",{"description":"ordinary text"}]`, core.Pass},
		{`{"description":"ordinary text"}`, core.NotApplicable}, {`[{},{}]`, core.NotApplicable},
		{`["https:example.org",{}]`, core.Fail}, {`[7]`, core.Error}, {`7`, core.Error},
	} {
		r := urlDoc(`{"id":"did:example:123","service":[{"serviceEndpoint":` + tc.value + `}]}`)
		got := judgeNativeURLs(r, "")
		if nativeVerdict(got, "services.13") != tc.want || nativeVerdict(got, "core-properties.1") != tc.want {
			t.Fatal(tc, got)
		}
		if nativeVerdict(got, "services.6") != core.NotApplicable {
			t.Fatal("optional id invented")
		}
	}
	r := urlDoc(`{"id":"did:example:123","verificationMethod":[],"service":[],"authentication":["did:example:123#k"]}`)
	if nativeVerdict(judgeNativeURLs(r, ""), "verification-methods.5") != core.NotApplicable {
		t.Fatal("reference is not embedded definition")
	}
	for _, doc := range []string{`{"id":"did:example:123","verificationMethod":7}`, `{"id":"did:example:123","authentication":7}`, `{"id":"did:example:123","assertionMethod":[7]}`} {
		if nativeVerdict(judgeNativeURLs(urlDoc(doc), ""), "verification-methods.5") != core.Error {
			t.Fatal(doc)
		}
	}
	if nativeVerdict(judgeNativeURLs(urlDoc(`{"id":"did:example:123","service":[7]}`), ""), "services.6") != core.Error {
		t.Fatal("invalid service set")
	}
}
func TestURLInspectionRejectsAbsentWrongVersionAndMalformedSnapshots(t *testing.T) {
	for _, change := range []func(*Result){
		func(r *Result) { r.HasContent = false }, func(r *Result) { r.ContentKind = "verification-method" },
		func(r *Result) { r.Metadata = json.RawMessage(`{`) }, func(r *Result) { r.Metadata = json.RawMessage(`{"error":{}}`) },
		func(r *Result) { r.Metadata = json.RawMessage(`{"contentType":"application/did+json"}`) },
		func(r *Result) { r.Snapshot = json.RawMessage(`{"id":"a","id":"b"}`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) },
		func(r *Result) { r.ContentMetadata = json.RawMessage(`{`) },
	} {
		r := nativeSchemaFixture("did-1.1")
		change(&r)
		for _, o := range judgeNativeURLs(r, "original") {
			if o.Verdict != core.Error || o.Input != "original" {
				t.Fatal(o)
			}
		}
	}
}
