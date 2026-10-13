package sageresolution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

type libraryDocumentFixture struct {
	Name      string             `json:"name"`
	Statement string             `json:"statement"`
	Positive  ConsumptionRequest `json:"positive"`
	Negative  ConsumptionRequest `json:"negative"`
}

func libraryDocumentFixtures() []libraryDocumentFixture {
	id := "did:sage:web:registry.example:agent-1"
	key, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	multikey := map[string]any{"id": id + "#sign", "type": "Multikey", "controller": id, "publicKeyMultibase": btcEncode(append([]byte{0xed, 0x01}, key...))}
	rows := []libraryDocumentFixture{}
	for _, name := range []string{"jwk-type", "multikey-type", "multikey-material", "also-known-as", "invocation", "delegation"} {
		var good map[string]any
		_ = json.Unmarshal([]byte(conformanceControl), &good)
		statement := ""
		var bad map[string]any
		if name == "multikey-type" || name == "multikey-material" {
			good["verificationMethod"] = []any{multikey}
		}
		switch name {
		case "jwk-type":
			statement = "cid10#JsonWebKey.1"
		case "multikey-type":
			statement = "cid10#Multikey.1"
		case "multikey-material":
			statement = "cid10#Multikey.3"
		case "also-known-as":
			statement = "cid10#also-known-as.2"
			good["alsoKnownAs"] = []any{"https://agent.example/profile", id}
		case "invocation":
			statement = "cid10#capability-invocation.2"
			good["capabilityInvocation"] = []any{id + "#sign"}
		case "delegation":
			statement = "cid10#capability-delegation.2"
			good["capabilityDelegation"] = []any{id + "#sign"}
		}
		positive, _ := json.Marshal(good)
		_ = json.Unmarshal(positive, &bad)
		switch name {
		case "jwk-type", "multikey-type":
			bad["verificationMethod"].([]any)[0].(map[string]any)["type"] = 42
		case "multikey-material":
			bad["verificationMethod"].([]any)[0].(map[string]any)["publicKeyMultibase"] = "z0"
		case "also-known-as":
			bad["alsoKnownAs"] = "https://agent.example/profile"
		case "invocation":
			bad["capabilityInvocation"] = []any{}
		case "delegation":
			bad["capabilityDelegation"] = []any{}
		}
		negative, _ := json.Marshal(bad)
		rows = append(rows, libraryDocumentFixture{name, statement, ConsumptionRequest{positive, "application/did"}, ConsumptionRequest{negative, "application/did"}})
	}
	return rows
}
func judgeLibraryDocument(f libraryDocumentFixture, pair consumerPair, input string) core.Observation {
	raw, _ := json.Marshal(pair)
	o := core.Observation{Statement: f.Statement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual accepted/preserved declared property and one-field invalid control refusal", Detail: "Fresh direct selected library consumer pair with explicit public documents. Known fixed JWK/Multikey type, valid public Multibase, URI set or nonempty capability relationship is present in the accepted control. Negative controls change only that field's syntax/shape. Default call arguments, original errors and accessor maps are retained. This is selected library document validation, not current SAGE record field support, optional-field absence, cryptographic safety, authorized controllers or full class/specification conformance."}
	if !libraryDocumentPremise(f) {
		return o
	}
	p, n := pair.Positive, pair.Negative
	if !sameConsumerCall(p, f.Positive) || !sameConsumerCall(n, f.Negative) || p.Error != "" || p.CaptureError != "" || p.Version != "1.1" || p.JSONLD || len(p.DroppedTerms) > 0 {
		return o
	}
	actual, e := parse(p.Model)
	expected, err := parse(f.Positive.Data)
	entries, ee := parse(p.Entries)
	equal, _ := checks.EqualJSON(actual.Value(), expected.Value())
	if e != nil || err != nil || ee != nil || len(entries.Members) > 0 || !equal {
		return o
	}
	o.Verdict = core.Fail
	if n.Error != "" && len(n.Model) == 0 && len(n.Entries) == 0 {
		o.Verdict = core.Pass
	}
	return o
}
func appendLibraryDocumentCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range libraryDocumentFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/library-document-%s", p.Name, f.Name), Profile: p.Name, Statements: []string{f.Statement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := consumerPair{}
			ids := []string{f.Statement}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return libraryUnavailable(ids, core.NotSupported, "no direct consumer", string(input), out)
			}
			good, e := s.InspectConsumption(ctx, f.Positive)
			out.Positive = good
			if e != nil {
				return libraryUnavailable(ids, core.Error, e.Error(), string(input), out)
			}
			bad, e := s.InspectConsumption(ctx, f.Negative)
			out.Negative = bad
			if e != nil {
				return libraryUnavailable(ids, core.Error, e.Error(), string(input), out)
			}
			return []core.Observation{judgeLibraryDocument(f, out, string(input))}
		}})
	}
}

func libraryDocumentPremise(f libraryDocumentFixture) bool {
	var good, bad map[string]any
	if json.Unmarshal(f.Positive.Data, &good) != nil || json.Unmarshal(f.Negative.Data, &bad) != nil {
		return false
	}
	id := "did:sage:web:registry.example:agent-1"
	if good["id"] != id || bad["id"] != id {
		return false
	}
	parent, field := "", ""
	valid := false
	switch f.Statement {
	case "cid10#JsonWebKey.1", "cid10#Multikey.1", "cid10#Multikey.3":
		parent = "verificationMethod"
		gm, gok := good[parent].([]any)
		bm, bok := bad[parent].([]any)
		if !gok || !bok || len(gm) != 1 || len(bm) != 1 {
			return false
		}
		g, gok := gm[0].(map[string]any)
		b, bok := bm[0].(map[string]any)
		if !gok || !bok {
			return false
		}
		field = "type"
		typ := "JsonWebKey"
		if f.Statement != "cid10#JsonWebKey.1" {
			typ = "Multikey"
		}
		valid = g["type"] == typ && b["type"] == float64(42)
		if f.Statement == "cid10#Multikey.3" {
			field = "publicKeyMultibase"
			v, ok := g[field].(string)
			key, e := checks.MultibaseDecode(v)
			expected, _ := hex.DecodeString("ed01d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
			valid = ok && e == nil && reflect.DeepEqual(key, expected) && g["type"] == "Multikey" && b[field] == "z0"
		}
	case "cid10#also-known-as.2":
		field = "alsoKnownAs"
		valid = reflect.DeepEqual(good[field], []any{"https://agent.example/profile", id}) && bad[field] == "https://agent.example/profile"
	case "cid10#capability-invocation.2", "cid10#capability-delegation.2":
		field = "capabilityInvocation"
		if f.Statement == "cid10#capability-delegation.2" {
			field = "capabilityDelegation"
		}
		valid = reflect.DeepEqual(good[field], []any{id + "#sign"}) && reflect.DeepEqual(bad[field], []any{})
	default:
		return false
	}
	left, _ := core.ParseJSON(f.Positive.Data)
	right, _ := core.ParseJSON(f.Negative.Data)
	descriptor := conformanceFixture{Parent: parent, Field: field}
	l, e := replaceFixtureField(left, descriptor, nil)
	r, err := replaceFixtureField(right, descriptor, nil)
	equal, _ := checks.EqualJSON(l, r)
	return valid && e == nil && err == nil && equal
}
