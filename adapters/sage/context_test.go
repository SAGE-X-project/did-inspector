package sage

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/sage-x-project/did-go/spec"
	"testing"
)

func TestActualLocalBaseContext(t *testing.T) {
	s := &Subject{}
	r, e := s.InspectBaseContext(t.Context())
	sum := sha256.Sum256(r.Data)
	if e != nil || r.Error != "" || r.Version != "1.1" || r.URL != "https://www.w3.org/ns/did/v1.1" || hex.EncodeToString(sum[:]) != "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85" {
		t.Fatal(r, e)
	}
}

func TestActualLocalBaseContextUnsupportedVersion(t *testing.T) {
	r := localBaseContext(spec.VUnknown)
	if r.Error == "" || len(r.Data) > 0 || r.URL != "" {
		t.Fatal("subject failure was hidden", r)
	}
}
