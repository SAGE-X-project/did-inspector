package inspectorprobe

import (
	"bytes"
	"testing"
)

func TestOriginalMultibaseUComponent(t *testing.T) {
	for _, f := range []struct {
		data    []byte
		encoded string
	}{{nil, "u"}, {[]byte{0}, "uA"}, {[]byte{1}, "uB"}, {[]byte{255}, "uD_"}, {[]byte{0, 0, 255}, "uAAD_"}, {[]byte{1, 2, 3}, "uQID"}} {
		got, err := EncodeMultibase('u', f.data)
		if err != nil || got != f.encoded {
			t.Fatal(got, err)
		}
		h, b, err := DecodeMultibase(f.encoded)
		if err != nil || h != 'u' || !bytes.Equal(b, f.data) {
			t.Fatal(err)
		}
	}
	if _, _, err := DecodeMultibase("u="); err == nil {
		t.Fatal("invalid alphabet")
	}
}
