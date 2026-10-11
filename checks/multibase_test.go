package checks

import (
	"bytes"
	"testing"
)

// TestMultibaseSpecExample decodes the Ed25519 public key of CID 1.0
// Example 9: the 34-byte value starts with the prefix 0xed01.
func TestMultibaseSpecExample(t *testing.T) {
	const v = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
	data, err := MultibaseDecode(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 34 || data[0] != 0xed || data[1] != 0x01 {
		t.Fatalf("decoded % x", data)
	}
	back, err := MultibaseEncode(MultibaseBase58BTC, data)
	if err != nil || back != v {
		t.Fatalf("encode = %q %v", back, err)
	}
}

func TestBaseEncodeKnownValues(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want string
	}{
		{nil, ""},
		{[]byte{0}, "1"},
		{[]byte{0, 0, 1}, "112"},
		{[]byte("hello world"), "StV1DL6CwTryKyV"},
		{[]byte{0xff}, "5Q"},
	} {
		if got := BaseEncode(tc.in, Base58BTCAlphabet); got != tc.want {
			t.Errorf("% x = %q, want %q", tc.in, got, tc.want)
		}
		back, err := BaseDecode(tc.want, Base58BTCAlphabet)
		if err != nil || !bytes.Equal(back, tc.in) && len(tc.in) > 0 {
			t.Errorf("decode %q = % x %v", tc.want, back, err)
		}
	}
	if got := BaseEncode([]byte{1}, Base64URLNoPadAlphabet); got != "B" {
		t.Errorf("base64 = %q", got)
	}
}

func TestMultibaseErrors(t *testing.T) {
	if _, err := MultibaseDecode(""); err == nil {
		t.Error("empty accepted")
	}
	if _, err := MultibaseDecode("f00"); err == nil {
		t.Error("header f accepted")
	}
	if _, err := MultibaseDecode("z0OIl"); err == nil {
		t.Error("characters outside base-58-btc accepted")
	}
	if _, err := MultibaseEncode('m', []byte{1}); err == nil {
		t.Error("header m accepted")
	}
	if v, err := MultibaseEncode(MultibaseBase64URL, []byte{0, 1}); err != nil || v != "uAB" {
		t.Errorf("u = %q %v", v, err)
	}
}
