package sage

import (
	"context"
	stdcrypto "crypto"
	"fmt"

	subjectcrypto "github.com/sage-x-project/did-go/crypto"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// InspectKeyConversion captures genuine public-key values around the delegated
// conversion. Published inputs remain local; no signing or key generation occurs.
func (*Subject) InspectKeyConversion(_ context.Context, q sageresolution.KeyConversionRequest) (sageresolution.KeyConversionResult, error) {
	return captureKeyConversion(q, subjectcrypto.NewPublicKey, subjectcrypto.FromCryptoKey), nil
}

func captureKeyConversion(q sageresolution.KeyConversionRequest, makeKey func(subjectcrypto.KeyType, []byte) (subjectcrypto.PublicKey, error), convert func(stdcrypto.PublicKey) (subjectcrypto.PublicKey, error)) sageresolution.KeyConversionResult {
	out := sageresolution.KeyConversionResult{Request: q, Operation: "github.com/sage-x-project/did-go/crypto.NewPublicKey+PublicKey.CryptoKey+FromCryptoKey+PublicKey.Multikey"}
	key, err := makeKey(subjectcrypto.KeyType(q.Name), q.Key)
	if err != nil {
		out.BuildError = err.Error()
		return out
	}
	out.BeforeRaw = key.Raw()
	out.BeforeType = string(key.Type())
	out.Before, err = key.Multikey()
	if err != nil {
		out.BeforeError = err.Error()
		return out
	}
	standard := key.CryptoKey()
	out.CryptoType = fmt.Sprintf("%T", standard)
	converted, err := convert(standard)
	if err != nil {
		out.ConvertError = err.Error()
		return out
	}
	out.AfterRaw = converted.Raw()
	out.AfterType = string(converted.Type())
	out.After, err = converted.Multikey()
	if err != nil {
		out.AfterError = err.Error()
	}
	return out
}
