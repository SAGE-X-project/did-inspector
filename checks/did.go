// Package checks is the inspector's own implementation of what the pinned
// specifications require, used to judge a subject's outputs. It is written
// from the specification text and shares no code with any subject.
//
// The DID and DID URL rules follow the ABNF of DID Core 1.0 §3.1 and §3.2,
// which DID 1.1 §3.1 and §3.2 repeat unchanged:
//
//	did                = "did:" method-name ":" method-specific-id
//	method-name        = 1*method-char
//	method-char        = %x61-7A / DIGIT
//	method-specific-id = *( *idchar ":" ) 1*idchar
//	idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
//	pct-encoded        = "%" HEXDIG HEXDIG
//	did-url            = did path-abempty [ "?" query ] [ "#" fragment ]
//
// ALPHA, DIGIT and HEXDIG are the core rules of RFC 5234; path-abempty,
// query and fragment are the rules of RFC 3986. Under RFC 5234 §2.3 a quoted
// string such as "did:" is case-insensitive, and HEXDIG, defined with quoted
// strings, accepts "a" to "f" as well as "A" to "F". method-char, defined
// with a value range, is lower-case only.
package checks

import (
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// SyntaxError reports where a string stops matching an ABNF rule.
type SyntaxError struct {
	// Input is the string checked.
	Input string
	// Rule is the ABNF rule that did not match.
	Rule string
	// Offset is the byte offset of the first character that did not match.
	Offset int
	// Reason describes the mismatch.
	Reason string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("%q does not match %s at offset %d: %s", e.Input, e.Rule, e.Offset, e.Reason)
}

const didPrefix = "did:"

// ParseDID checks s against the did rule and returns its components.
func ParseDID(s string) (core.DIDParts, error) {
	parts, end, serr := scanDID(s)
	if serr != nil {
		return core.DIDParts{}, serr
	}
	if end != len(s) {
		return core.DIDParts{}, &SyntaxError{Input: s, Rule: "did", Offset: end, Reason: fmt.Sprintf("unexpected %q", s[end])}
	}
	return parts, nil
}

// IsDID reports whether s matches the did rule.
func IsDID(s string) bool {
	_, err := ParseDID(s)
	return err == nil
}

// scanDID matches the did rule at the start of s and returns the offset
// after it. The method-specific-id runs as far as idchar and ":" allow;
// the did rule cannot end with ":".
func scanDID(s string) (core.DIDParts, int, *SyntaxError) {
	if len(s) < len(didPrefix) || !strings.EqualFold(s[:len(didPrefix)], didPrefix) {
		return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "did", Offset: 0, Reason: `missing "did:"`}
	}
	i := len(didPrefix)
	start := i
	for i < len(s) && isMethodChar(s[i]) {
		i++
	}
	if i == start {
		return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "method-name", Offset: i, Reason: "needs at least one lower-case letter or digit"}
	}
	method := s[start:i]
	if i >= len(s) || s[i] != ':' {
		return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "did", Offset: i, Reason: `expected ":" after method-name`}
	}
	i++
	idStart := i
scan:
	for i < len(s) {
		switch {
		case s[i] == ':' || isIDCharByte(s[i]):
			i++
		case s[i] == '%':
			if !isPctEncoded(s, i) {
				return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "pct-encoded", Offset: i, Reason: `"%" must be followed by two HEXDIG`}
			}
			i += 3
		default:
			break scan
		}
	}
	msid := s[idStart:i]
	if msid == "" {
		return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "method-specific-id", Offset: i, Reason: "needs at least one idchar"}
	}
	if msid[len(msid)-1] == ':' {
		return core.DIDParts{}, 0, &SyntaxError{Input: s, Rule: "method-specific-id", Offset: i - 1, Reason: `cannot end with ":"`}
	}
	return core.DIDParts{DID: s[:i], Method: method, MethodSpecificID: msid}, i, nil
}

// ParseDIDURL checks s against the did-url rule and returns its components.
func ParseDIDURL(s string) (core.DIDURLParts, error) {
	did, i, serr := scanDID(s)
	if serr != nil {
		return core.DIDURLParts{}, serr
	}
	out := core.DIDURLParts{DIDURL: s, DID: did}
	rest := s[i:]
	beforeFrag, frag, hasFrag := strings.Cut(rest, "#")
	path, query, hasQuery := strings.Cut(beforeFrag, "?")
	if path != "" && path[0] != '/' {
		return core.DIDURLParts{}, &SyntaxError{Input: s, Rule: "did-url", Offset: i, Reason: fmt.Sprintf("unexpected %q after the DID", path[0])}
	}
	if off, err := checkRule(path, isPathAbemptyChar, "path-abempty"); err != nil {
		return core.DIDURLParts{}, withOffset(err, s, i+off)
	}
	queryStart := i + len(path) + 1
	if off, err := checkRule(query, isQueryOrFragmentChar, "query"); err != nil {
		return core.DIDURLParts{}, withOffset(err, s, queryStart+off)
	}
	fragStart := i + len(beforeFrag) + 1
	if off, err := checkRule(frag, isQueryOrFragmentChar, "fragment"); err != nil {
		return core.DIDURLParts{}, withOffset(err, s, fragStart+off)
	}
	out.Path = path
	out.Query, out.HasQuery = query, hasQuery
	out.Fragment, out.HasFragment = frag, hasFrag
	return out, nil
}

// IsDIDURL reports whether s matches the did-url rule.
func IsDIDURL(s string) bool {
	_, err := ParseDIDURL(s)
	return err == nil
}

func withOffset(err *SyntaxError, input string, offset int) *SyntaxError {
	err.Input = input
	err.Offset = offset
	return err
}

func isMethodChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || isDigit(c)
}

// isIDCharByte matches idchar except pct-encoded.
func isIDCharByte(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '.' || c == '-' || c == '_'
}

func isAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isHexDig matches HEXDIG of RFC 5234, which is case-insensitive.
func isHexDig(c byte) bool {
	return isDigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}

// isPctEncoded reports whether s[i:] starts with pct-encoded.
func isPctEncoded(s string, i int) bool {
	return i+2 < len(s) && s[i] == '%' && isHexDig(s[i+1]) && isHexDig(s[i+2])
}
