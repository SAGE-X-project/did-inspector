package checks

// RFC 3986 rules used by the did-url rule:
//
//	path-abempty  = *( "/" segment )
//	segment       = *pchar
//	query         = *( pchar / "/" / "?" )
//	fragment      = *( pchar / "/" / "?" )
//	pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//	unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//	sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//	              / "*" / "+" / "," / ";" / "="
//	pct-encoded   = "%" HEXDIG HEXDIG

// IsPathAbempty reports whether s matches path-abempty: empty, or a
// sequence of "/" segment.
func IsPathAbempty(s string) bool {
	if s != "" && s[0] != '/' {
		return false
	}
	_, err := checkRule(s, isPathAbemptyChar, "path-abempty")
	return err == nil
}

// IsQuery reports whether s matches the query rule.
func IsQuery(s string) bool {
	_, err := checkRule(s, isQueryOrFragmentChar, "query")
	return err == nil
}

// IsFragment reports whether s matches the fragment rule.
func IsFragment(s string) bool {
	_, err := checkRule(s, isQueryOrFragmentChar, "fragment")
	return err == nil
}

// checkRule checks that every character of s is allowed by the rule or
// starts a pct-encoded triplet, and returns the offset of the first one that
// is not.
func checkRule(s string, allowed func(byte) bool, rule string) (int, *SyntaxError) {
	for i := 0; i < len(s); {
		switch {
		case s[i] == '%':
			if !isPctEncoded(s, i) {
				return i, &SyntaxError{Input: s, Rule: rule, Offset: i, Reason: `"%" must be followed by two HEXDIG`}
			}
			i += 3
		case allowed(s[i]):
			i++
		default:
			return i, &SyntaxError{Input: s, Rule: rule, Offset: i, Reason: "character " + quoteByte(s[i]) + " is not allowed"}
		}
	}
	return 0, nil
}

func quoteByte(c byte) string {
	if c >= 0x21 && c <= 0x7e {
		return `"` + string(rune(c)) + `"`
	}
	const hex = "0123456789ABCDEF"
	return "0x" + string(hex[c>>4]) + string(hex[c&0xf])
}

func isUnreserved(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

func isSubDelim(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	}
	return false
}

// isPChar matches pchar except pct-encoded.
func isPChar(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@'
}

// isPathAbemptyChar matches the characters of path-abempty except
// pct-encoded: pchar and the "/" that starts each segment.
func isPathAbemptyChar(c byte) bool {
	return isPChar(c) || c == '/'
}

func isQueryOrFragmentChar(c byte) bool {
	return isPChar(c) || c == '/' || c == '?'
}

// PercentEncode percent-encodes every octet of s that is not unreserved
// (RFC 3986 §2.1, §2.3), with uppercase hexadecimal digits. The HTTP(S)
// binding of DID Resolution §12.1 URL-encodes the input DID this way when it
// sends options as query parameters.
func PercentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			out = append(out, c)
			continue
		}
		out = append(out, '%', hex[c>>4], hex[c&0x0f])
	}
	return string(out)
}
