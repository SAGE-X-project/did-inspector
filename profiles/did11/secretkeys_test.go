package did11

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
)

// TestSecretKeyVectors decodes every Multikey vector with the inspector's
// own Multibase decoder and checks the bytes against the row of CID 1.0
// §2.2.2 the vector claims: the conforming vector has the row's two-byte
// prefix and key length, the length vectors differ by one byte, and the
// header u vector has the conforming bytes.
func TestSecretKeyVectors(t *testing.T) {
	for _, row := range secretKeyRows() {
		g := rowGroup(row)
		var conforming []byte
		for i, v := range g.Vectors {
			m, _ := v.Method.Get(secretMultibase)
			data, err := checks.MultibaseDecode(m.Str)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if !bytes.HasPrefix(data, row.prefix[:]) {
				t.Errorf("%s: prefix % x", v.Name, data[:2])
			}
			n := len(data) - 2
			switch {
			case i == 0:
				conforming = data
				if !v.Valid || m.Str[0] != 'z' || n != len(row.key) {
					t.Errorf("%s: valid=%v header %c length %d", v.Name, v.Valid, m.Str[0], n)
				}
			case strings.HasSuffix(v.Name, "header u"):
				if v.Valid || m.Str[0] != 'u' || !bytes.Equal(data, conforming) {
					t.Errorf("%s: valid=%v header %c", v.Name, v.Valid, m.Str[0])
				}
			default:
				if v.Valid || (n != len(row.key)-1 && n != len(row.key)+1) {
					t.Errorf("%s: valid=%v length %d", v.Name, v.Valid, n)
				}
			}
		}
	}
	lengths := map[string]int{"p-256": 32, "p-384": 48, "ed25519": 32, "bls12-381-g2": 96, "sm2": 32}
	for _, row := range secretKeyRows() {
		if len(row.key) != lengths[row.name] {
			t.Errorf("%s: %d bytes", row.name, len(row.key))
		}
	}
	if _, err := ecdh.P256().NewPrivateKey(p256Secret()); err != nil {
		t.Error(err)
	}
	if v := sm2Secret(); len(v) != 32 {
		t.Errorf("sm2 = % x", v)
	}
}

// TestSecretKeyJWK checks that the Ed25519 secretKeyJwk carries the public
// key of its seed.
func TestSecretKeyJWK(t *testing.T) {
	g := jwkGroup()
	jwk, _ := g.Vectors[1].Method.Get(secretJWK)
	x, _ := jwk.Get("x")
	pub := ed25519.NewKeyFromSeed(ed25519Seed()).Public().(ed25519.PublicKey)
	if !strings.HasPrefix(g.Vectors[1].Name, "JsonWebKey with an Ed25519") || x.Str != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatalf("vector = %+v", g.Vectors[1])
	}
}
