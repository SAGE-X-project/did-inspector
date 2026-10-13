package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

var keyFieldStatements = []string{"cid10#services.3", "cid10#verification-material.1", "cid10#JsonWebKey.7"}

func selectedMaterial(method core.Value) core.Verdict {
	typ, _ := method.Get("type")
	if typ.Kind != core.KindString || typ.Str != "JsonWebKey" {
		return core.NotSupported
	}
	// An unknown extension can name additional material; do not assume it cannot.
	known := map[string]bool{"id": true, "type": true, "controller": true, "publicKeyJwk": true, "publicKeyMultibase": true, "expires": true, "revoked": true}
	for _, member := range method.Object {
		if !known[member.Name] {
			return core.NotSupported
		}
	}
	jwk, hasJWK := method.Get("publicKeyJwk")
	mb, hasMB := method.Get("publicKeyMultibase")
	if !hasJWK || !hasMB {
		return core.Pass
	}
	// Only the pinned CID Ed25519 0xed01 header has dual-format comparison here.
	kty, _ := jwk.Get("kty")
	crv, _ := jwk.Get("crv")
	x, _ := jwk.Get("x")
	if kty.Str != "OKP" || crv.Str != "Ed25519" || mb.Kind != core.KindString {
		return core.NotSupported
	}
	key, ok := strictJWKBytes(x, 32)
	encoded, err := checks.MultibaseDecode(mb.Str)
	if !ok || err != nil || len(encoded) != 34 || encoded[0] != 0xed || encoded[1] != 0x01 {
		return core.NotSupported
	}
	if bytes.Equal(key, encoded[2:]) {
		return core.Fail
	}
	return core.NotSupported // Different bytes do not prove independent material.
}
func selectedAlg(method core.Value) core.Verdict {
	typ, _ := method.Get("type")
	if typ.Kind != core.KindString || typ.Str != "JsonWebKey" {
		return core.NotSupported
	}
	jwk, present := method.Get("publicKeyJwk")
	if !present {
		return core.NotApplicable
	}
	if jwk.Kind != core.KindObject {
		return core.Fail
	}
	alg, present := jwk.Get("alg")
	if !present || alg.Kind != core.KindString || alg.Str == "" {
		return core.Fail
	}
	return core.Pass // Presence only; no algorithm registry or crypto equivalence claim.
}
func judgeKeyFields(result Result, input string) []core.Observation {
	missing := func(detail string) []core.Observation {
		out := unavailable(keyFieldStatements, core.Error, detail)
		for i := range out {
			out[i].Input = input
		}
		return out
	}
	if result.Exchange != nil || result.Native != nil || !result.HasContent || result.ContentKind != "document" {
		return missing("fresh native document required")
	}
	md, err := parse(result.Metadata)
	if err != nil {
		return missing(err.Error())
	}
	ct, _ := md.Get("contentType")
	_, failed := md.Get("error")
	if ct.Kind != core.KindString || ct.Str != "application/did" || failed {
		return missing("native DID 1.1 document required")
	}
	doc, err := parse(result.Snapshot)
	if err != nil {
		return missing(err.Error())
	}
	_, err = parse(result.ContentMetadata)
	if err != nil {
		return missing(err.Error())
	}
	methods, err := nativeURLMethods(doc)
	if err != nil {
		return missing(err.Error())
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return missing(err.Error())
	}
	serviceVerdict := core.NotApplicable
	if services, present := doc.Get("service"); present {
		serviceVerdict = core.Pass
		if !nativeMaps(services) {
			serviceVerdict = core.Fail
		} else {
			for _, service := range services.Array {
				for _, name := range []string{"id", "type", "serviceEndpoint"} {
					if _, present := service.Get(name); !present {
						serviceVerdict = core.Fail
					}
				}
			}
		}
	}
	material, alg := []core.Verdict{}, []core.Verdict{}
	for _, method := range methods {
		material = append(material, selectedMaterial(method))
		alg = append(alg, selectedAlg(method))
	}
	aggregate := func(values []core.Verdict) core.Verdict {
		if len(values) == 0 {
			return core.NotApplicable
		}
		return core.Aggregate(values)
	}
	verdicts := []core.Verdict{serviceVerdict, aggregate(material), aggregate(alg)}
	out := make([]core.Observation, 0, 3)
	for i, id := range keyFieldStatements {
		out = append(out, core.Observation{Statement: id, Verdict: verdicts[i], Input: input, Expected: "Selected native service members, duplicate material, recommended JWK alg presence", Observed: string(raw), Detail: "Fresh DID 1.1 accessor and metadata observations; no projection verdict or subject validator is used. Only selected JsonWebKey material names and equal Ed25519 public bytes are compared; unknown types/aliases and other dual formats remain NOT_SUPPORTED. alg presence is recommended, not mandatory, and absence is a recommendation FAIL. Actual last Update history/authority, alg compatibility, cryptographic security and whole document conformance are unestablished."})
	}
	return out
}
func appendKeyFieldCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-key-fields-record-%d", p.Name, i), Profile: p.Name, Statements: append([]string{}, keyFieldStatements...), Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			missing := func(v core.Verdict, detail string) []core.Observation {
				out := unavailable(keyFieldStatements, v, detail)
				for i := range out {
					out[i].Input = string(input)
				}
				return out
			}
			subject, ok := target.(Subject)
			if !ok {
				return missing(core.NotSupported, "no native document observation")
			}
			result, err := subject.InspectResolution(ctx, record, q)
			if err != nil {
				return missing(core.Error, err.Error())
			}
			return judgeKeyFields(result, string(input))
		}})
	}
}
