package checks

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// IsASCII reports whether s is an ASCII string: every code unit is below
// 0x80 (Infra Standard, "ASCII string").
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// IsKeyword reports whether s is a single keyword ASCII string, as DID Core
// 1.0 §7.1.2 and §7.2.2 require for error values: a non-empty run of ASCII
// letters, digits, "-", "_" and ".", without white space or other
// separators (for example "invalidDid" or "notFound").
func IsKeyword(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// isTChar matches tchar of RFC 9110 §5.6.2.
func isTChar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func scanToken(s string, i int) int {
	for i < len(s) && isTChar(s[i]) {
		i++
	}
	return i
}

func skipOWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// scanQuoted matches quoted-string of RFC 9110 §5.6.4 at s[i] and returns
// the offset after it, or -1.
func scanQuoted(s string, i int) int {
	i++
	for i < len(s) {
		switch c := s[i]; {
		case c == '"':
			return i + 1
		case c == '\\' && i+1 < len(s):
			i += 2
		case c == '\t' || (c >= 0x20 && c != 0x7f):
			i++
		default:
			return -1
		}
	}
	return -1
}

// IsMediaType reports whether s matches media-type of RFC 9110 §8.3.1:
// type "/" subtype *( OWS ";" OWS parameter ), where parameter is
// token "=" ( token / quoted-string ). The parameter part may be empty
// after a ";", as RFC 9110 allows.
func IsMediaType(s string) bool {
	i := scanToken(s, 0)
	if i == 0 || i >= len(s) || s[i] != '/' {
		return false
	}
	j := scanToken(s, i+1)
	if j == i+1 {
		return false
	}
	return parametersAt(s, j)
}

func parametersAt(s string, i int) bool {
	for {
		i = skipOWS(s, i)
		if i == len(s) {
			return true
		}
		if s[i] != ';' {
			return false
		}
		i = skipOWS(s, i+1)
		if i == len(s) || s[i] == ';' {
			continue
		}
		n := scanToken(s, i)
		if n == i || n >= len(s) || s[n] != '=' {
			return false
		}
		switch {
		case n+1 < len(s) && s[n+1] == '"':
			i = scanQuoted(s, n+1)
			if i < 0 {
				return false
			}
		default:
			v := scanToken(s, n+1)
			if v == n+1 {
				return false
			}
			i = v
		}
	}
}

// MediaTypeEssence returns the type and subtype of a media type in lower
// case, without parameters; media type names are case-insensitive (RFC 9110
// §8.3.1).
func MediaTypeEssence(s string) string {
	essence, _, _ := strings.Cut(s, ";")
	return strings.ToLower(strings.TrimSpace(essence))
}

// IsAbsoluteURI reports whether s is a URI of RFC 3986 §3 with a scheme:
// scheme ":" followed only by characters a URI may contain (unreserved,
// reserved and pct-encoded) and at most one "#". It does not check the
// component structure beyond that.
func IsAbsoluteURI(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon < 1 || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < colon; i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	if strings.Count(s, "#") > 1 {
		return false
	}
	_, err := checkRule(s[colon+1:], isURIChar, "URI")
	return err == nil
}

// isURIChar matches unreserved and reserved characters of RFC 3986 §2.
func isURIChar(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || strings.IndexByte(":/?#[]@", c) >= 0
}

// ErrURIList reports content that is not a text/uri-list.
var ErrURIList = errors.New("not a text/uri-list")

// ParseURIList parses text/uri-list content (RFC 2483 §5): lines that are
// URIs, comment lines starting with "#", lines ended by CRLF. A bare LF is
// accepted as a line end too. Every non-comment line must be an absolute
// URI; empty content is an empty list.
func ParseURIList(content []byte) ([]string, error) {
	var out []string
	for n, line := range bytes.Split(content, []byte("\n")) {
		s := strings.TrimSuffix(string(line), "\r")
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if !IsAbsoluteURI(s) {
			return nil, fmt.Errorf("%w: line %d %q is not an absolute URI", ErrURIList, n+1, s)
		}
		out = append(out, s)
	}
	return out, nil
}
