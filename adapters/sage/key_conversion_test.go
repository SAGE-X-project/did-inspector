package sage

import (
	"bytes"
	stdcrypto "crypto"
	"encoding/hex"
	"errors"
	subjectcrypto "github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualPublicKeyConversion(t *testing.T) {
	raw, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	q := sageresolution.KeyConversionRequest{Name: "Ed25519", Key: raw}
	out, err := (&Subject{}).InspectKeyConversion(t.Context(), q)
	if err != nil || out.BuildError != "" || out.BeforeError != "" || out.ConvertError != "" || out.AfterError != "" || out.CryptoType != "ed25519.PublicKey" || out.Before != out.After || !bytes.Equal(out.BeforeRaw, raw) || !bytes.Equal(out.AfterRaw, raw) {
		t.Fatal(out, err)
	}
	q.Key = nil
	out, err = (&Subject{}).InspectKeyConversion(t.Context(), q)
	if err != nil || out.BuildError == "" && out.BeforeError == "" && out.ConvertError == "" && out.AfterError == "" || out.Before != "" || out.After != "" {
		t.Fatal("failed construction lost", out, err)
	}
}
func TestConversionCaptureRetainsStageErrors(t *testing.T) {
	raw, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	q := sageresolution.KeyConversionRequest{Name: "Ed25519", Key: raw}
	makeZero := func(subjectcrypto.KeyType, []byte) (subjectcrypto.PublicKey, error) {
		return subjectcrypto.PublicKey{}, nil
	}
	convertError := func(stdcrypto.PublicKey) (subjectcrypto.PublicKey, error) {
		return subjectcrypto.PublicKey{}, errors.New("conversion refused")
	}
	convertZero := func(stdcrypto.PublicKey) (subjectcrypto.PublicKey, error) { return subjectcrypto.PublicKey{}, nil }
	for _, out := range []sageresolution.KeyConversionResult{
		captureKeyConversion(q, makeZero, subjectcrypto.FromCryptoKey),
		captureKeyConversion(q, subjectcrypto.NewPublicKey, convertError),
		captureKeyConversion(q, subjectcrypto.NewPublicKey, convertZero),
	} {
		if out.BuildError == "" && out.BeforeError == "" && out.ConvertError == "" && out.AfterError == "" || out.After != "" {
			t.Fatal("stage refusal lost", out)
		}
	}
}
