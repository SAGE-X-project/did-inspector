package sageresolution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"math/big"
	"reflect"
)

// This table is transcribed independently from pinned CID clauses. Subject
// registry rows and validation annotations are never an expectation oracle.
type codecFixture struct {
	Name       string   `json:"name"`
	Prefix     []byte   `json:"prefix"`
	Length     int      `json:"length"`
	Secret     bool     `json:"secret"`
	Statements []string `json:"statements"`
}

func codecFixtures() []codecFixture {
	rows := []codecFixture{
		{"P-256", []byte{0x80, 0x24}, 33, false, []string{"cid10#Multikey.6", "cid10#Multikey.7"}},
		{"P-384", []byte{0x81, 0x24}, 49, false, []string{"cid10#Multikey.8"}},
		{"Ed25519", []byte{0xed, 0x01}, 32, false, []string{"cid10#Multikey.9", "cid10#Multikey.10"}},
		{"BLS12-381-G2", []byte{0xeb, 0x01}, 96, false, []string{"cid10#Multikey.11", "cid10#Multikey.12"}},
		{"SM2", []byte{0x86, 0x24}, 33, false, []string{"cid10#Multikey.13", "cid10#Multikey.14"}},
		{"P-256", []byte{0x86, 0x26}, 32, true, []string{"cid10#Multikey.15", "cid10#Multikey.16"}},
		{"P-384", []byte{0x87, 0x26}, 48, true, []string{"cid10#Multikey.17"}},
		{"Ed25519", []byte{0x80, 0x26}, 32, true, []string{"cid10#Multikey.18", "cid10#Multikey.19"}},
		{"SM2", []byte{0x90, 0x26}, 32, true, []string{"cid10#Multikey.22", "cid10#Multikey.23"}},
	}
	for i := range rows {
		rows[i].Statements = append(rows[i].Statements, "cid10#multibase-0.2", "cid10#multibase-0.4")
	}
	return rows
}

const btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// btcEncode is an inspector-only integer oracle, independent of did-go.
func btcEncode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	radix := big.NewInt(58)
	digit := new(big.Int)
	out := []byte{}
	for n.Sign() > 0 {
		n.QuoRem(n, radix, digit)
		out = append(out, btcAlphabet[digit.Int64()])
	}
	for _, b := range data {
		if b != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return "z" + string(out)
}

// Public points are fixed published vectors: RFC5114 sections2.6/2.7,
// RFC8032 section7.1, RFC8998 section3.2.1 and BBS signatures draft12
// appendixB BP2. The second Weierstrass/BLS point is the negative point.
func codecRequests(f codecFixture) []CodecRequest {
	public := map[string]string{
		"P-256":        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"P-384":        "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"Ed25519":      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"BLS12-381-G2": "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
		"SM2":          "0232c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
	}
	rows := []CodecRequest{}
	for pattern := 0; pattern < 2; pattern++ {
		key := make([]byte, f.Length)
		if f.Secret {
			key[len(key)-1] = byte(pattern + 1)
		} else {
			key, _ = hex.DecodeString(public[f.Name])
			if pattern == 1 {
				switch f.Name {
				case "Ed25519":
					key, _ = hex.DecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
				case "BLS12-381-G2":
					key[0] ^= 0x20
				default:
					if len(key) > 0 {
						key[0] ^= 1
					}
				}
			}
		}
		encoded := btcEncode(append(append([]byte{}, f.Prefix...), key...))
		rows = append(rows, CodecRequest{Name: f.Name, Secret: f.Secret, Key: key, Encoded: encoded})
	}
	return rows
}
func judgeCodec(f codecFixture, out []CodecResult, input string) []core.Observation {
	requests := codecRequests(f)
	verdict := core.Pass
	if len(out) != len(requests) {
		verdict = core.Error
	} else {
		for i, r := range out {
			if r.Operation != "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey" || !reflect.DeepEqual(r.Request, requests[i]) {
				verdict = core.Error
				break
			}
			if r.EncodeError != "" || r.DecodeError != "" || r.Name != f.Name || r.Length != f.Length || r.Secret != f.Secret || !bytes.Equal(r.Prefix, f.Prefix) || r.Encoded != requests[i].Encoded || r.DecodeName != f.Name || r.DecodeLength != f.Length || r.DecodeSecret != f.Secret || !bytes.Equal(r.DecodePrefix, f.Prefix) || !bytes.Equal(r.Decoded, requests[i].Key) {
				verdict = core.Fail
				break
			}
		}
	}
	raw, _ := json.Marshal(out)
	obs := unavailable(f.Statements, verdict, "Actual selected library codec encode and independently supplied decode input. Checks only the CID row's prefix/byte-length/base58 encoding contract using two public deterministic test inputs: published public points and public scalar/seed test bytes. No signing or operational keys are used; cryptographic validation, secret custody, method type and every internal arithmetic step are not established. Conflicting BLS secret rows remain unobserved.")
	for i := range obs {
		obs[i].Input = input
		obs[i].Observed = string(raw)
		obs[i].Expected = "Pinned literal prefix/length and independent base58-btc string with z header"
	}
	return obs
}
func appendLibraryCodecCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range codecFixtures() {
		role := "public"
		if f.Secret {
			role = "secret"
		}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/library-codec-%s-%s", p.Name, f.Name, role), Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Fixture  codecFixture   `json:"fixture"`
				Requests []CodecRequest `json:"requests"`
			}{f, codecRequests(f)})
			out := []CodecResult{}
			s, ok := target.(CodecSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no direct library codec observer", string(input), out)
			}
			for _, q := range codecRequests(f) {
				r, e := s.InspectCodec(ctx, q)
				if e != nil {
					return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
				}
				out = append(out, r)
			}
			return judgeCodec(f, out, string(input))
		}})
	}
}
