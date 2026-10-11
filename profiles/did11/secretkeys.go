package did11

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// The secret key encodings of CID 1.0 §2.2.2 (secretKeyMultibase) and
// §2.2.3 (secretKeyJwk) are judged on standalone verification methods: a
// controlled identifier document is data that may be revealed, in which
// cid10#JsonWebKey.12 forbids secret keys, so no published document can
// carry them conformingly. The vectors are computed here from key material
// derived with the standard library and encoded with the inspector's own
// Multibase implementation (checks.MultibaseEncode, CID 1.0 §2.4 and
// §3.1); nothing is copied from the subject.
//
// Each verification method carries the secret key property alone, as
// Example 11 of CID 1.0 §2.2.3 does for secretKeyJwk, and each vector is
// judged only by the findings about that property.

const (
	vmController = "did:example:vm"
	vmID         = vmController + "#key-1"
)

// secretKeyRow is one row of the Multikey secret key table of CID 1.0
// §2.2.2.
type secretKeyRow struct {
	name   string
	prefix [2]byte
	key    []byte
	// prefixStatement judges the prefix and length; encodingStatement the
	// base-58-btc encoding with the header z, or "" where the row states
	// it without MUST (P-384: "is then encoded").
	prefixStatement, encodingStatement string
}

// secretKeyRows returns the table's rows with secret key data of the
// stated length:
//
//   - P-256 (0x8626, 32 bytes) and P-384 (0x8726, 48 bytes): scalars that
//     crypto/ecdh accepts as private keys of the curve;
//   - Ed25519 (0x8026, 32 bytes): an Ed25519 seed (RFC 8032 §5.1.5);
//   - BLS12-381 G2 (0x8030, 96 bytes): the row states "followed by the
//     96-byte compressed public key data", so 96 bytes follow;
//   - SM2 (0x9026, 32 bytes): a scalar below the order of the SM2 curve
//     (GB/T 32918.5, n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123).
func secretKeyRows() []secretKeyRow {
	return []secretKeyRow{
		{"p-256", [2]byte{0x86, 0x26}, p256Secret(), c("Multikey.15"), c("Multikey.16")},
		{"p-384", [2]byte{0x87, 0x26}, p384Secret(), c("Multikey.17"), ""},
		{"ed25519", [2]byte{0x80, 0x26}, ed25519Seed(), c("Multikey.18"), c("Multikey.19")},
		{"bls12-381-g2", [2]byte{0x80, 0x30}, derive("bls12-381-g2", 96), c("Multikey.20"), c("Multikey.21")},
		{"sm2", [2]byte{0x90, 0x26}, sm2Secret(), c("Multikey.22"), c("Multikey.23")},
	}
}

// derive returns n deterministic bytes for a label.
func derive(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		sum := sha512.Sum512([]byte(fmt.Sprintf("did-inspector/%s/%d", label, i)))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

func ed25519Seed() []byte { return derive("ed25519", ed25519.SeedSize) }

func p256Secret() []byte { return ecdhScalar(ecdh.P256(), "p-256", 32) }

func p384Secret() []byte { return ecdhScalar(ecdh.P384(), "p-384", 48) }

// ecdhScalar returns the first derived scalar the curve accepts as a
// private key.
func ecdhScalar(curve ecdh.Curve, label string, n int) []byte {
	for i := 0; ; i++ {
		d := derive(fmt.Sprintf("%s/%d", label, i), n)
		if _, err := curve.NewPrivateKey(d); err == nil {
			return d
		}
	}
}

var sm2Order, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

func sm2Secret() []byte {
	for i := 0; ; i++ {
		d := derive(fmt.Sprintf("sm2/%d", i), 32)
		if v := new(big.Int).SetBytes(d); v.Sign() > 0 && v.Cmp(sm2Order) < 0 {
			return d
		}
	}
}

// multikey returns header followed by the encoding of prefix and key.
func multikey(header byte, prefix [2]byte, key []byte) string {
	v, err := checks.MultibaseEncode(header, append(prefix[:], key...))
	if err != nil {
		panic(err)
	}
	return v
}

// method returns a standalone verification method with the given type and
// one more member.
func method(typ, name string, value core.Value) core.DocumentJSON {
	return core.NewDocument(
		core.M("id", core.String(vmID)),
		core.M("type", core.String(typ)),
		core.M("controller", core.String(vmController)),
		core.M(name, value),
	)
}

const secretMultibase = "secretKeyMultibase"

// rowGroup returns the vectors of one secret key row: the conforming
// encoding, key data one byte short and one byte long, and, where the row
// requires base-58-btc, the same bytes encoded with the header u.
func rowGroup(row secretKeyRow) kit.VMGroup {
	encStatements := []string{row.prefixStatement}
	if row.encodingStatement != "" {
		encStatements = append(encStatements, row.encodingStatement)
	}
	vec := func(name string, value string, valid bool, why string, sts ...string) kit.VMVector {
		return kit.VMVector{Name: name, Method: method("Multikey", secretMultibase, core.String(value)), Property: secretMultibase, Valid: valid, Why: why, Statements: sts}
	}
	n := len(row.key)
	g := kit.VMGroup{Case: "multikey-secret-" + row.name, Vectors: []kit.VMVector{
		vec(fmt.Sprintf("%s secret key: prefix %#x%02x and %d bytes, base-58-btc", row.name, row.prefix[0], row.prefix[1], n),
			multikey(checks.MultibaseBase58BTC, row.prefix, row.key), true, "", encStatements...),
		vec(fmt.Sprintf("%s secret key with %d bytes", row.name, n-1),
			multikey(checks.MultibaseBase58BTC, row.prefix, row.key[:n-1]), false, fmt.Sprintf("the key data must be %d bytes", n), row.prefixStatement),
		vec(fmt.Sprintf("%s secret key with %d bytes", row.name, n+1),
			multikey(checks.MultibaseBase58BTC, row.prefix, append(append([]byte{}, row.key...), 0x01)), false, fmt.Sprintf("the key data must be %d bytes", n), row.prefixStatement),
	}}
	if row.encodingStatement != "" {
		g.Vectors = append(g.Vectors, vec(row.name+" secret key encoded with the header u",
			multikey(checks.MultibaseBase64URL, row.prefix, row.key), false, "the value must be base-58-btc with the header z", row.encodingStatement))
	}
	return g
}

// multibaseGroup judges secretKeyMultibase as an optional Multibase value
// (cid10#Multikey.4, cid10#Multikey.5).
func multibaseGroup() kit.VMGroup {
	seed := ed25519Seed()
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	secret := multikey(checks.MultibaseBase58BTC, [2]byte{0x80, 0x26}, seed)
	optional, value := []string{c("Multikey.4")}, []string{c("Multikey.5")}
	bad := func(name string, v core.Value, why string) kit.VMVector {
		return kit.VMVector{Name: name, Method: method("Multikey", secretMultibase, v), Property: secretMultibase, Why: why, Statements: value}
	}
	return kit.VMGroup{Case: "multikey-secret-multibase", Vectors: []kit.VMVector{
		{Name: "Multikey without secretKeyMultibase", Property: secretMultibase, Valid: true, Statements: optional,
			Method: method("Multikey", "publicKeyMultibase", core.String(multikey(checks.MultibaseBase58BTC, [2]byte{0xed, 0x01}, pub)))},
		{Name: "Multikey with a base-58-btc secretKeyMultibase", Property: secretMultibase, Valid: true, Statements: kit.Union(optional, value),
			Method: method("Multikey", secretMultibase, core.String(secret))},
		bad("secretKeyMultibase that is empty", core.String(""), "a Multibase value starts with a header character"),
		bad("secretKeyMultibase with characters outside base-58-btc", core.String("z0OIl"), "0, O, I and l are not in the base-58-btc alphabet"),
		bad("secretKeyMultibase with characters outside base-64-url-no-pad", core.String("u+/="), "+, / and = are not in the base-64-url-no-pad alphabet"),
		bad("secretKeyMultibase that is a number", core.Number("42"), "a Multibase value is a string"),
	}}
}

const secretJWK = "secretKeyJwk"

// jwkGroup judges secretKeyJwk as an optional JSON Web Key
// (cid10#JsonWebKey.10, cid10#JsonWebKey.11).
func jwkGroup() kit.VMGroup {
	b64 := base64.RawURLEncoding.EncodeToString
	seed := ed25519Seed()
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	okp := func(extra ...core.Member) core.Value {
		return core.Object(append([]core.Member{core.M("kty", core.String("OKP")), core.M("crv", core.String("Ed25519")),
			core.M("d", core.String(b64(seed))), core.M("x", core.String(b64(pub)))}, extra...)...)
	}
	d384 := p384Secret()
	k384, err := ecdh.P384().NewPrivateKey(d384)
	if err != nil {
		panic(err)
	}
	point := k384.PublicKey().Bytes() // 0x04 || X || Y (SEC 1 §2.3.3)
	ec := core.Object(core.M("kty", core.String("EC")), core.M("crv", core.String("P-384")), core.M("d", core.String(b64(d384))),
		core.M("x", core.String(b64(point[1:49]))), core.M("y", core.String(b64(point[49:]))))
	optional, value := []string{c("JsonWebKey.10")}, []string{c("JsonWebKey.11")}
	bad := func(name string, v core.Value, why string) kit.VMVector {
		return kit.VMVector{Name: name, Method: method("JsonWebKey", secretJWK, v), Property: secretJWK, Why: why, Statements: value}
	}
	noKty := core.Object(core.M("crv", core.String("Ed25519")), core.M("d", core.String(b64(seed))), core.M("x", core.String(b64(pub))))
	numKty := core.Object(core.M("kty", core.Number("1")), core.M("crv", core.String("Ed25519")), core.M("d", core.String(b64(seed))), core.M("x", core.String(b64(pub))))
	return kit.VMGroup{Case: "jwk-secret", Partial: "judged by the JSON object form and the kty member RFC 7517 §4.1 requires of every JWK; key-type parameters of RFC 7518 and RFC 8037 are not judged", Vectors: []kit.VMVector{
		{Name: "JsonWebKey without secretKeyJwk", Property: secretJWK, Valid: true, Statements: optional,
			Method: method("JsonWebKey", "publicKeyJwk", core.Object(core.M("kty", core.String("OKP")), core.M("crv", core.String("Ed25519")), core.M("x", core.String(b64(pub)))))},
		{Name: "JsonWebKey with an Ed25519 secretKeyJwk", Property: secretJWK, Valid: true, Statements: kit.Union(optional, value), Method: method("JsonWebKey", secretJWK, okp())},
		{Name: "JsonWebKey with a P-384 secretKeyJwk", Property: secretJWK, Valid: true, Statements: value, Method: method("JsonWebKey", secretJWK, ec)},
		bad("secretKeyJwk that is a string", core.String(b64(seed)), "a JSON Web Key is a JSON object (RFC 7517 §4)"),
		bad("secretKeyJwk that is an array", core.Array(okp()), "a JSON Web Key is a JSON object (RFC 7517 §4)"),
		bad("secretKeyJwk without kty", noKty, `"kty" MUST be present in a JWK (RFC 7517 §4.1)`),
		bad("secretKeyJwk whose kty is a number", numKty, `the "kty" value is a case-sensitive string (RFC 7517 §4.1)`),
	}}
}

// secretKeyGroups returns the verification method groups of the profile.
func secretKeyGroups() []kit.VMGroup {
	groups := []kit.VMGroup{multibaseGroup()}
	for _, row := range secretKeyRows() {
		groups = append(groups, rowGroup(row))
	}
	return append(groups, jwkGroup())
}
