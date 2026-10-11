package checks

import (
	"errors"
	"fmt"
	"strings"
)

// Multibase headers and base alphabets of Controlled Identifiers 1.0 §2.4.
const (
	MultibaseBase58BTC     = 'z'
	MultibaseBase64URL     = 'u'
	Base58BTCAlphabet      = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	Base64URLNoPadAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// BaseEncode is the Base Encode algorithm of CID 1.0 §3.1 for a base
// alphabet whose size is the target base: leading zero bytes become
// leading first characters, and the rest is converted by integer base
// expansion.
func BaseEncode(data []byte, alphabet string) string {
	base := len(alphabet)
	zeroes := 0
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	// digits holds the base-encoded value, most significant digit first.
	var digits []int
	for _, b := range data[zeroes:] {
		carry := int(b)
		for i := len(digits) - 1; i >= 0; i-- {
			carry += digits[i] * 256
			digits[i] = carry % base
			carry /= base
		}
		for carry > 0 {
			digits = append([]int{carry % base}, digits...)
			carry /= base
		}
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat(alphabet[:1], zeroes))
	for _, d := range digits {
		sb.WriteByte(alphabet[d])
	}
	return sb.String()
}

// BaseDecode is the Base Decode algorithm of CID 1.0 §3.2: the inverse of
// BaseEncode. A character outside the alphabet is an error.
func BaseDecode(s, alphabet string) ([]byte, error) {
	base := len(alphabet)
	zeroes := 0
	for zeroes < len(s) && s[zeroes] == alphabet[0] {
		zeroes++
	}
	// value holds the decoded bytes, most significant first.
	var value []byte
	for i := zeroes; i < len(s); i++ {
		carry := strings.IndexByte(alphabet, s[i])
		if carry < 0 {
			return nil, fmt.Errorf("checks: character %q at %d is not in the base-%d alphabet", s[i], i, base)
		}
		for j := len(value) - 1; j >= 0; j-- {
			carry += int(value[j]) * base
			value[j] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			value = append([]byte{byte(carry % 256)}, value...)
			carry /= 256
		}
	}
	return append(make([]byte, zeroes), value...), nil
}

// MultibaseEncode encodes data as a Multibase value with one of the two
// headers CID 1.0 §2.4 defines: z (base-58-btc) or u (base-64-url-no-pad).
func MultibaseEncode(header byte, data []byte) (string, error) {
	alphabet, err := multibaseAlphabet(header)
	if err != nil {
		return "", err
	}
	return string(header) + BaseEncode(data, alphabet), nil
}

// MultibaseDecode decodes a Multibase value with the header z or u.
func MultibaseDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("checks: empty Multibase value")
	}
	alphabet, err := multibaseAlphabet(s[0])
	if err != nil {
		return nil, err
	}
	return BaseDecode(s[1:], alphabet)
}

func multibaseAlphabet(header byte) (string, error) {
	switch header {
	case MultibaseBase58BTC:
		return Base58BTCAlphabet, nil
	case MultibaseBase64URL:
		return Base64URLNoPadAlphabet, nil
	}
	return "", fmt.Errorf("checks: Multibase header %q is not one CID 1.0 §2.4 defines", header)
}
