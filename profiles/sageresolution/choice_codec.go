package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/sage-x-project/did-inspector/core"
)

var choiceCodecIDs = []string{"cid10#algorithms.1", "cid10#multibase-0.3", "cid10#multibase-0.5"}

// Equivalent output is checked through public codec operations. These cases
// do not establish reference-algorithm assignments, loops or all inputs.
func judgeChoiceCodec(f codecFixture, values []CodecResult, input string) []core.Observation {
	obs := libraryUnavailable(choiceCodecIDs, core.Error, "Actual pinned public Multikey codec calls, compared with an independent integer base58 oracle. Selected published vectors only; no inference about internal algorithm steps, arbitrary alphabets, every input or cryptographic key validity. Encoder and decoder outcomes are judged separately. Malformed base58 input is diagnostic only, outside the valid-input equivalence verdict; its error shape is not a normative predicate.", input, values)
	qs := codecRequests(f)
	bad := qs[0]
	bad.Encoded = "z0"
	qs = append(qs, bad)
	if len(values) != len(qs) {
		return obs
	}
	encOK, decOK := true, true
	for i, v := range values {
		if v.Operation != "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey" || !reflect.DeepEqual(v.Request, qs[i]) {
			return obs
		}
		encOK = encOK && v.EncodeError == "" && v.Encoded == btcEncode(append(append([]byte{}, f.Prefix...), qs[i].Key...)) && v.Name == f.Name && v.Length == f.Length && v.Secret == f.Secret && bytes.Equal(v.Prefix, f.Prefix)
		if i < len(qs)-1 {
			decOK = decOK && v.DecodeError == "" && bytes.Equal(v.Decoded, qs[i].Key) && v.DecodeName == f.Name && v.DecodeLength == f.Length && v.DecodeSecret == f.Secret && bytes.Equal(v.DecodePrefix, f.Prefix)
		}
		// Malformed input is retained for diagnostics only: these equivalence
		// clauses specify no error shape for a character outside the alphabet.
	}
	for i, ok := range []bool{encOK && decOK, encOK, decOK} {
		obs[i].Verdict = core.Fail
		if ok {
			obs[i].Verdict = core.Pass
		}
		obs[i].Expected = "Equivalent base58 encoding/decoding for the selected published key bytes; malformed decoder input remains diagnostic evidence only"
	}
	return obs
}

func appendChoiceCodecCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range codecFixtures() {
		role := "public"
		if f.Secret {
			role = "public-test-secret"
		}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/choice-codec-%s-%s", p.Name, f.Name, role), Profile: p.Name, Statements: choiceCodecIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			qs := codecRequests(f)
			bad := qs[0]
			bad.Encoded = "z0"
			qs = append(qs, bad)
			in, _ := json.Marshal(qs)
			subject, ok := target.(CodecSubject)
			if !ok {
				return libraryUnavailable(choiceCodecIDs, core.NotSupported, "no direct codec observer", string(in), nil)
			}
			values := []CodecResult{}
			for _, q := range qs {
				v, err := subject.InspectCodec(ctx, q)
				values = append(values, v)
				if err != nil {
					return libraryUnavailable(choiceCodecIDs, core.Error, err.Error(), string(in), values)
				}
			}
			return judgeChoiceCodec(f, values, string(in))
		}})
	}
}
