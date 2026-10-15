package inspectorprobe

import (
	"bytes"
	"testing"
)

func TestOriginalComponentCalls(t *testing.T) {
	for _, pair := range []struct {
		code uint64
		n    int
	}{{0x12, 32}, {0x20, 48}, {0x16, 32}, {0x15, 48}} {
		digest := make([]byte, pair.n)
		for i := range digest {
			digest[i] = byte(i)
		}
		want := append([]byte{byte(pair.code), byte(pair.n)}, digest...)
		got, err := Encode(pair.code, digest)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("encode", err)
		}
		code, decoded, err := Decode(want)
		if err != nil || code != pair.code || !bytes.Equal(decoded, digest) {
			t.Fatal("decode", err)
		}
		decoded[0] = 99
		if want[2] != 0 {
			t.Fatal("alias")
		}
		if _, err := Encode(pair.code, digest[:len(digest)-1]); err == nil {
			t.Fatal("encode length")
		}

		for _, bad := range [][]byte{append([]byte{byte(pair.code), byte(pair.n - 1)}, digest[:len(digest)-1]...), append([]byte{byte(pair.code), byte(pair.n + 1)}, append(digest, byte(pair.n))...)} {
			if _, _, err := Decode(bad); err == nil {
				t.Fatal("header expected length")
			}
		}
		if _, _, err := Decode(want[:len(want)-1]); err == nil {
			t.Fatal("decode length")
		}
	}
}
