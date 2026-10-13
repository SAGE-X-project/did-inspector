package sageresolution

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

//go:embed jwk-parameters-20261013.csv
var jwkParameterBytes []byte

const jwkRegistryHash = "e897697bbbfc6df505806acbead93009b9b9534bfd45ce82c6158e6767cc0871"

var publicJWKStatements = []string{"cid10#JsonWebKey.3", "cid10#JsonWebKey.4", "cid10#JsonWebKey.8", "cid10#JsonWebKey.12", "cid10#JsonWebKey.13"}

type jwkClassification struct{ private, secret, registered map[string]bool }

func jwkRegistry() (jwkClassification, error) {
	hash := sha256.Sum256(jwkParameterBytes)
	if hex.EncodeToString(hash[:]) != jwkRegistryHash {
		return jwkClassification{}, fmt.Errorf("IANA JWK parameter snapshot drift")
	}
	rows, err := csv.NewReader(bytes.NewReader(jwkParameterBytes)).ReadAll()
	if err != nil {
		return jwkClassification{}, err
	}
	c := jwkClassification{map[string]bool{}, map[string]bool{}, map[string]bool{}}
	for _, row := range rows[1:] {
		name, kind := row[0], row[3]
		c.registered[name] = true
		switch kind {
		case "Private":
			c.private[name] = true
		case "Secret":
			c.secret[name] = true
		}
	}
	return c, nil
}
func jwkMethods(d core.DocumentJSON) ([]core.Value, error) {
	result := []core.Value{}
	if values, present := d.Get("verificationMethod"); present {
		if !nativeMaps(values) {
			return nil, fmt.Errorf("invalid native method set")
		}
		for _, method := range values.Array {
			typ, _ := method.Get("type")
			if typ.Kind == core.KindString && typ.Str == "JsonWebKey" {
				result = append(result, method)
			}
		}
	}
	for _, name := range []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"} {
		values, present := d.Get(name)
		if !present {
			continue
		}
		if values.Kind != core.KindArray {
			return nil, fmt.Errorf("invalid native relationship set")
		}
		for _, method := range values.Array {
			if method.Kind != core.KindObject {
				continue
			}
			typ, _ := method.Get("type")
			if typ.Kind == core.KindString && typ.Str == "JsonWebKey" {
				result = append(result, method)
			}
		}
	}
	return result, nil
}
func strictJWKBytes(v core.Value, n int) ([]byte, bool) {
	if v.Kind != core.KindString || v.Str == "" {
		return nil, false
	}
	for i := range v.Str {
		ch := v.Str[i]
		allowed := ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_'
		if !allowed {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(v.Str)
	return b, err == nil && len(b) == n && base64.RawURLEncoding.EncodeToString(b) == v.Str
}
func publicJWKFormat(j core.Value, c jwkClassification) core.Verdict {
	if j.Kind != core.KindObject {
		return core.Fail
	}
	kty, _ := j.Get("kty")
	if kty.Kind != core.KindString || kty.Str == "" {
		return core.Fail
	}
	crv, _ := j.Get("crv")
	if kty.Str != "EC" && kty.Str != "OKP" {
		return core.NotSupported
	}
	if crv.Kind != core.KindString || crv.Str == "" {
		return core.Fail
	}
	supported := kty.Str == "EC" && crv.Str == "P-256" || kty.Str == "OKP" && (crv.Str == "Ed25519" || crv.Str == "X25519")
	if !supported {
		return core.NotSupported
	}
	// Optional registered metadata/certificates and non-public material have
	// separate semantics. Never call their uninspected format conformant.
	for _, member := range j.Object {
		switch member.Name {
		case "kty", "crv", "x":
			continue
		case "y":
			if kty.Str == "EC" {
				continue
			}
		}
		if c.registered[member.Name] {
			return core.NotSupported
		}
	}
	x, _ := j.Get("x")
	xb, ok := strictJWKBytes(x, 32)
	if !ok {
		return core.Fail
	}
	if kty.Str == "EC" {
		y, _ := j.Get("y")
		yb, ok := strictJWKBytes(y, 32)
		if !ok {
			return core.Fail
		}
		point := append(append([]byte{4}, xb...), yb...)
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return core.Fail
		}
	}
	// OKP checks octet encoding/length only, not mathematical point validity,
	// small-order safety, signature use, KEM use or operational provenance.
	return core.Pass
}
func jwkCurve(j core.Value) core.Verdict {
	if j.Kind != core.KindObject {
		return core.Error
	}
	kty, _ := j.Get("kty")
	if kty.Kind != core.KindString {
		return core.Error
	}
	if kty.Str == "RSA" || kty.Str == "oct" {
		return core.NotApplicable
	}
	if kty.Str != "EC" && kty.Str != "OKP" {
		return core.NotSupported
	}
	crv, _ := j.Get("crv")
	if crv.Kind != core.KindString || crv.Str == "" {
		return core.Fail
	}
	if kty.Str == "EC" && crv.Str == "P-256" || kty.Str == "OKP" && (crv.Str == "Ed25519" || crv.Str == "X25519") {
		return core.Pass
	}
	return core.NotSupported
}
func jwkMemberVerdict(method core.Value, id string, c jwkClassification) core.Verdict {
	if id == "cid10#JsonWebKey.12" {
		if _, present := method.Get("secretKeyJwk"); present {
			return core.Fail
		}
		return core.Pass
	}
	j, present := method.Get("publicKeyJwk")
	if !present {
		return core.NotApplicable
	}
	switch id {
	case "cid10#JsonWebKey.3":
		return publicJWKFormat(j, c)
	case "cid10#JsonWebKey.8":
		return jwkCurve(j)
	}
	if j.Kind != core.KindObject {
		return core.Error
	}
	for _, member := range j.Object {
		if c.private[member.Name] || id == "cid10#JsonWebKey.13" && c.secret[member.Name] {
			return core.Fail
		}
	}
	return core.Pass
}
func judgePublicJWK(o Result, c jwkClassification, input string) []core.Observation {
	fail := func(detail string) []core.Observation {
		obs := unavailable(publicJWKStatements, core.Error, detail)
		for i := range obs {
			obs[i].Input = input
		}
		return obs
	}
	md, err := parse(o.Metadata)
	if err != nil {
		return fail(err.Error())
	}
	mt, _ := md.Get("contentType")
	if !o.HasContent || o.ContentKind != "document" || mt.Kind != core.KindString || checks.MediaTypeEssence(mt.Str) != "application/did" {
		return fail("public JWK inspection requires actual DID 1.1 document")
	}
	if _, failed := md.Get("error"); failed {
		return fail("native resolution failed")
	}
	doc, err := parse(o.Snapshot)
	if err != nil {
		return fail(err.Error())
	}
	methods, err := jwkMethods(doc)
	if err != nil {
		return fail(err.Error())
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return fail(err.Error())
	}
	obs := make([]core.Observation, 0, len(publicJWKStatements))
	for _, id := range publicJWKStatements {
		verdicts := []core.Verdict{}
		for _, method := range methods {
			verdicts = append(verdicts, jwkMemberVerdict(method, id, c))
		}
		verdict := core.NotApplicable
		if len(verdicts) > 0 {
			verdict = core.Aggregate(verdicts)
		}
		obs = append(obs, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Selected public EC P-256 / OKP Ed25519 or X25519 JWK format, curve identifier and pinned registered non-public member exclusion", Observed: string(raw), Detail: "Actual public fixture DID 1.1 accessor document; IANA JWK parameters sha256=" + jwkRegistryHash + ". Unknown key/curve or uninspected registered metadata formats remain NOT_SUPPORTED. OKP point mathematics, signature/KEM operations, certificate semantics, authority and general JWK conformance are unestablished. No verdict is copied or key field repaired."})
	}
	return obs
}
func appendPublicJWKCases(p *core.Profile, rows []sageprojection.Record) error {
	if p.Name != "did-1.1" {
		return nil
	}
	c, err := jwkRegistry()
	if err != nil {
		return err
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/public-jwk-record-%d", p.Name, i), Profile: p.Name, Statements: append([]string{}, publicJWKStatements...), Run: func(ctx context.Context, s core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			target, ok := s.(Subject)
			if !ok {
				obs := unavailable(publicJWKStatements, core.NotSupported, "no native resolution operation")
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			result, err := target.InspectResolution(ctx, record, q)
			if err != nil {
				obs := unavailable(publicJWKStatements, core.Error, err.Error())
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			return judgePublicJWK(result, c, string(input))
		}})
	}
	return nil
}
