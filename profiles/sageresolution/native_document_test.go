package sageresolution

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func nativeSchemaFixture(name string) Result {
	r := native()
	r.ContentKind = "document"
	typ := "JsonWebKey2020"
	if name == "did-1.1" {
		typ = "JsonWebKey"
		r.Metadata = json.RawMessage(`{"contentType":"application/did"}`)
	}
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"id":"did:sage:web:x:a#sign","type":"` + typ + `","controller":"did:sage:web:x:a","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"public-fixture"}}],"authentication":["did:sage:web:x:a#sign"],"assertionMethod":["did:sage:web:x:a#sign"],"keyAgreement":["did:sage:web:x:a#sign"],"service":[{"id":"did:sage:web:x:a#a2a","type":"A2AInterface","serviceEndpoint":"https://example.org/a2a"}]}`)
	return r
}
func nativeVerdict(obs []core.Observation, suffix string) core.Verdict {
	for _, o := range obs {
		if strings.HasSuffix(o.Statement, "#"+suffix) {
			return o.Verdict
		}
	}
	return ""
}
func TestNativeFieldRulesHaveIndependentNegativeControls(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		good := nativeSchemaFixture(name)
		obs := judgeNativeDocument(good, name, "input")
		for _, o := range obs {
			if o.Verdict != core.Pass || o.Input != "input" || !strings.Contains(o.Observed, "snapshot") {
				t.Fatal(o)
			}
		}
		for _, tc := range []struct{ old, new, rule string }{
			{`"verificationMethod":[{`, `"verificationMethod":[7,{`, "verification-methods.2"},
			{`"publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"public-fixture"}`, `"publicKeyJwk":null`, "verification-methods.3"},
			{`"authentication":["did:sage:web:x:a#sign"]`, `"authentication":[]`, "authentication.2"},
			{`"assertionMethod":["did:sage:web:x:a#sign"]`, `"assertionMethod":[7]`, "assertion.2"},
			{`"keyAgreement":["did:sage:web:x:a#sign"]`, `"keyAgreement":["did:sage:web:x:a#sign","did:sage:web:x:a#sign"]`, "key-agreement.2"},
			{`"service":[{`, `"service":[7,{`, "services.2"},
		} {
			bad := good
			bad.Snapshot = json.RawMessage(strings.Replace(string(good.Snapshot), tc.old, tc.new, 1))
			if nativeVerdict(judgeNativeDocument(bad, name, ""), tc.rule) != core.Fail {
				t.Fatal(name, tc)
			}
		}
		for _, tc := range []struct{ old, new, legacy, cid string }{
			{`"id":"did:sage:web:x:a#sign"`, `"id":7`, "verification-methods.6", "verification-methods.5"},
			{`"controller":"did:sage:web:x:a"`, `"controller":7`, "verification-methods.9", "verification-methods.7"},
			{`"type":"JsonWebKey2020"`, `"type":[]`, "verification-methods.7", "verification-methods.6"},
			{`"type":"A2AInterface"`, `"type":[7]`, "services.8", "services.9"},
			{`"serviceEndpoint":"https://example.org/a2a"`, `"serviceEndpoint":[]`, "services.10", "services.12"},
		} {
			old := tc.old
			if name == "did-1.1" {
				old = strings.ReplaceAll(old, "JsonWebKey2020", "JsonWebKey")
			}
			bad := good
			bad.Snapshot = json.RawMessage(strings.Replace(string(good.Snapshot), old, tc.new, 1))
			rule := tc.legacy
			if name == "did-1.1" {
				rule = tc.cid
				if rule == "verification-methods.5" || rule == "verification-methods.7" {
					continue
				}
			}
			if nativeVerdict(judgeNativeDocument(bad, name, ""), rule) != core.Fail {
				t.Fatal(name, tc)
			}
		}
	}
}
func TestNativeRulesPreserveConditionalAbsentAndEmptySets(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		r := nativeSchemaFixture(name)
		r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a"}`)
		for _, o := range judgeNativeDocument(r, name, "") {
			if strings.Contains(o.Statement, "subject") {
				if o.Verdict != core.Pass {
					t.Fatal(o)
				}
			} else if o.Verdict != core.NotApplicable {
				t.Fatal(o)
			}
		}
		r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[],"service":[]}`)
		obs := judgeNativeDocument(r, name, "")
		for _, id := range []string{"verification-methods.2", "services.2"} {
			if nativeVerdict(obs, id) != core.Pass {
				t.Fatal(id)
			}
		}
		if nativeVerdict(obs, "verification-methods.3") != core.NotApplicable {
			t.Fatal("empty set invents material check")
		}
	}
}
func TestNativeVersionExecutionAndJSONErrorsAreNotPass(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		for _, change := range []func(*Result){
			func(r *Result) { r.HasContent = false }, func(r *Result) { r.ContentKind = "verification-method" },
			func(r *Result) { r.Metadata = json.RawMessage(`{`) }, func(r *Result) {
				r.Metadata = json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
			},
			func(r *Result) { r.Snapshot = json.RawMessage(`{"id":"a","id":"b"}`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) },
		} {
			r := nativeSchemaFixture(name)
			change(&r)
			for _, o := range judgeNativeDocument(r, name, "original") {
				if o.Verdict != core.Error || o.Input != "original" {
					t.Fatal(o)
				}
			}
		}
	}
	for _, md := range []string{`{}`, `{"contentType":"application/did+json"}`, `{"contentType":7}`} {
		r := nativeSchemaFixture("did-1.1")
		r.Metadata = json.RawMessage(md)
		for _, o := range judgeNativeDocument(r, "did-1.1", "") {
			if o.Verdict != core.Error {
				t.Fatal("wrong version checked", o)
			}
		}
	}
	r := nativeSchemaFixture("did-1.1")
	r.Metadata = json.RawMessage(`{"contentType":"Application/DID"}`)
	for _, o := range judgeNativeDocument(r, "did-1.1", "") {
		if o.Verdict != core.Pass {
			t.Fatal("media type case", o)
		}
	}
}
func TestNativeServiceConditionalIDsAndMandatoryProperties(t *testing.T) {
	r := nativeSchemaFixture("did-1.1")
	for _, tc := range []struct {
		service string
		rule    string
		want    core.Verdict
	}{
		{`[{"type":"A","serviceEndpoint":"https://example.org"}]`, "services.7", core.Pass},
		{`[{"id":"#x","type":"A","serviceEndpoint":{}},{"id":"#x","type":"B","serviceEndpoint":{}}]`, "services.7", core.Fail},
		{`[{"serviceEndpoint":{}}]`, "services.8", core.Fail},
		{`[{"type":"A"}]`, "services.11", core.Fail},
	} {
		r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","service":` + tc.service + `}`)
		if nativeVerdict(judgeNativeDocument(r, "did-1.1", ""), tc.rule) != tc.want {
			t.Fatal(tc)
		}
	}
	r = nativeSchemaFixture("did-core-1.0")
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","service":[{"type":"A","serviceEndpoint":{}}]}`)
	if nativeVerdict(judgeNativeDocument(r, "did-core-1.0", ""), "services.3") != core.Fail {
		t.Fatal("Core1.0 id omission")
	}
}
func TestNativeSetAndRelationshipShapes(t *testing.T) {
	for _, s := range []string{`"A"`, `[]`, `["A","B"]`} {
		v, _ := core.ParseJSON([]byte(s))
		if !nativeStrings(v) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`7`, `["A","A"]`} {
		v, _ := core.ParseJSON([]byte(s))
		if nativeStrings(v) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`"https://example.org"`, `{}`, `[{},"https://example.org"]`} {
		v, _ := core.ParseJSON([]byte(s))
		if !nativeEndpoint(v) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`7`, `[7]`, `[{},{}]`, `[]`} {
		v, _ := core.ParseJSON([]byte(s))
		if nativeEndpoint(v) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`{"authentication":[{"id":"did:example:1#k","type":"JsonWebKey","controller":"did:example:1","publicKeyJwk":{}}]}`, `{"authentication":["did:example:1#k"]}`} {
		d, _ := parse([]byte(s))
		a, p := nativeRelationship("authentication")(d)
		if !a || !p {
			t.Fatal(s)
		}
	}
	for _, s := range []string{`{"authentication":[{}]}`, `{"authentication":["did:INVALID:x"]}`, `{"authentication":{}}`} {
		d, _ := parse([]byte(s))
		a, p := nativeRelationship("authentication")(d)
		if !a || p {
			t.Fatal(s)
		}
	}
}

func TestUnknownNativeMethodsAndReferencesAreNotPromoted(t *testing.T) {
	r := nativeSchemaFixture("did-1.1")
	for _, typ := range []string{"Multikey", "OtherRegisteredKey"} {
		r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"id":"did:sage:web:x:a#k","type":"` + typ + `","controller":"did:sage:web:x:a","publicKeyMultibase":"public-fixture"}],"authentication":[{"id":"#k","type":"` + typ + `","controller":"did:sage:web:x:a","publicKeyMultibase":"public-fixture"}]}`)
		obs := judgeNativeDocument(r, "did-1.1", "")
		for _, id := range []string{"verification-methods.3", "verification-methods.6", "authentication.2"} {
			if nativeVerdict(obs, id) != core.NotSupported {
				t.Fatal(typ, id, obs)
			}
		}
		if nativeVerdict(obs, "JsonWebKey.1") != "" {
			t.Fatal("unrelated method class", obs)
		}
	}
	for _, ref := range []string{"https://example.org/key", "https://", "#k"} {
		r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","authentication":["` + ref + `"]}`)
		if nativeVerdict(judgeNativeDocument(r, "did-1.1", ""), "authentication.2") != core.NotSupported {
			t.Fatal(ref)
		}
	}
	for _, rules := range [][]nativeRule{nativeDocumentRules("did-1.1")} {
		for _, rule := range rules {
			if rule.id == "cid10#verification-methods.5" || rule.id == "cid10#verification-methods.7" || rule.id == "cid10#JsonWebKey.1" {
				t.Fatal("unobserved URL or material-type clause connected")
			}
		}
	}
	d, _ := parse([]byte(`{"authentication":[{"id":"#k","type":"JsonWebKey","controller":"did:example:1"}]}`))
	applies, pass := nativeRelationship("authentication")(d)
	if !applies || pass {
		t.Fatal("known JWK without material")
	}
}

func TestNativeRootAndMethodTypesAreIndependentlyChecked(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		r := nativeSchemaFixture(name)
		r.Snapshot = json.RawMessage(`{}`)
		suffix := "did-subject.1"
		if name == "did-1.1" {
			suffix = "subjects.2"
		}
		if nativeVerdict(judgeNativeDocument(r, name, ""), suffix) != core.Fail {
			t.Fatal("missing root id", name)
		}
	}
	r := nativeSchemaFixture("did-core-1.0")
	r.Snapshot = json.RawMessage(`{"id":"invalid"}`)
	if nativeVerdict(judgeNativeDocument(r, "did-core-1.0", ""), "did-subject.1") != core.Fail {
		t.Fatal("Core root syntax")
	}
	r = nativeSchemaFixture("did-1.1")
	r.ContentMetadata = json.RawMessage(`{`)
	for _, o := range judgeNativeDocument(r, "did-1.1", "original") {
		if o.Verdict != core.Error || o.Input != "original" {
			t.Fatal("unserializable result", o)
		}
	}
}
