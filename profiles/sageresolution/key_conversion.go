package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/sage-x-project/did-inspector/core"
)

var keyConversionIDs = []string{"cid10#verification-material.2", "cid10#verification-material.3"}

const keyConversionOperation = "github.com/sage-x-project/did-go/crypto.NewPublicKey+PublicKey.CryptoKey+FromCryptoKey+PublicKey.Multikey"

func keyConversionFixtures() []codecFixture {
	out := []codecFixture{}
	for _, f := range codecFixtures() {
		if !f.Secret && (f.Name == "Ed25519" || f.Name == "P-256" || f.Name == "P-384") {
			out = append(out, f)
		}
	}
	return out
}
func judgeKeyConversion(f codecFixture, values []KeyConversionResult, input string) []core.Observation {
	obs := libraryUnavailable(keyConversionIDs, core.Error, "Actual public-key conversion through the standard library representation and back, with independent published point bytes and base58 expected strings. Only the chosen public key types and external Multikey value are checked; no claim about all formats, private keys, signatures, document conversion or operational custody.", input, values)
	qs := codecRequests(f)
	if len(values) != len(qs) {
		return obs
	}
	converted, observedAfter, unchanged := true, true, true
	applicable := 0
	for i, v := range values {
		q := KeyConversionRequest{Name: f.Name, Key: qs[i].Key}
		if v.Operation != keyConversionOperation || !reflect.DeepEqual(v.Request, q) || v.BuildError != "" || v.BeforeError != "" || v.Before != qs[i].Encoded {
			return obs
		}
		if v.ConvertError != "" {
			if v.After != "" || len(v.AfterRaw) > 0 || v.AfterType != "" || v.AfterError != "" {
				return obs
			}
			converted = false
			continue
		}
		applicable++
		// Raw, model type and standard-library type are diagnostic internal
		// representations, not the external-value invariance predicate.
		if v.AfterError != "" {
			observedAfter = false
			continue
		}
		unchanged = unchanged && v.After == qs[i].Encoded
	}
	obs[0].Verdict = core.Pass
	obs[0].Expected = "The selected public-key conversion is exercised; a refused optional conversion is not a mandatory-rule violation"
	if !converted {
		obs[0].Verdict = core.NotSupported
		obs[1].Detail += " Refused conversions with no external output are excluded from the preservation predicate; successful conversions remain independently checked."
	}
	obs[1].Expected = "The original conforming external Multikey encoding is unchanged after actual conversion"
	if applicable == 0 {
		obs[1].Verdict = core.NotApplicable
		return obs
	}
	if !observedAfter && unchanged {
		return obs
	}
	obs[1].Verdict = core.Fail
	if unchanged {
		obs[1].Verdict = core.Pass
	}
	return obs
}
func appendKeyConversionCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range keyConversionFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/choice-key-conversion-%s", p.Name, f.Name), Profile: p.Name, Statements: keyConversionIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			qs := []KeyConversionRequest{}
			for _, q := range codecRequests(f) {
				qs = append(qs, KeyConversionRequest{Name: f.Name, Key: q.Key})
			}
			input, _ := json.Marshal(qs)
			subject, ok := target.(KeyConversionSubject)
			if !ok {
				return libraryUnavailable(keyConversionIDs, core.NotSupported, "no actual public-key conversion observer", string(input), nil)
			}
			out := []KeyConversionResult{}
			for _, q := range qs {
				v, err := subject.InspectKeyConversion(ctx, q)
				out = append(out, v)
				if err != nil {
					return libraryUnavailable(keyConversionIDs, core.Error, err.Error(), string(input), out)
				}
			}
			return judgeKeyConversion(f, out, string(input))
		}})
	}
}
