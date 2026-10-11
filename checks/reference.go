package checks

import (
	"fmt"
	"strings"
)

// uriRef is the five components of a URI reference (RFC 3986 §3), with
// the presence of the optional ones.
type uriRef struct {
	scheme, authority, path, query, fragment   string
	hasScheme, hasAuthority, hasQuery, hasFrag bool
}

// splitReference splits a URI reference with the regular expression of
// RFC 3986 Appendix B, written out by hand.
func splitReference(s string) uriRef {
	var r uriRef
	if i := strings.IndexByte(s, '#'); i >= 0 {
		r.fragment, r.hasFrag, s = s[i+1:], true, s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		r.query, r.hasQuery, s = s[i+1:], true, s[:i]
	}
	if i := strings.IndexAny(s, ":/"); i > 0 && s[i] == ':' {
		r.scheme, r.hasScheme, s = s[:i], true, s[i+1:]
	}
	if rest, ok := strings.CutPrefix(s, "//"); ok {
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		r.authority, r.hasAuthority, s = rest[:end], true, rest[end:]
	}
	r.path = s
	return r
}

// ResolveDIDReference resolves a DID URL reference against a base DID with
// the Reference Resolution algorithm of RFC 3986 §5.2, as DID Core 1.0
// §3.2.2 instructs: "The base URI value is the DID that is associated with
// the DID subject ... The scheme is did. The authority is a combination of
// <method-name>:<method-specific-id>, and the path, query, and fragment
// values are those defined in Path, Query, and Fragment, respectively."
// The base DID therefore has the authority method-name:method-specific-id
// and an empty path, and the result is written back in the DID URL form
// (without the "//" of RFC 3986 §5.3, which a DID does not have).
//
// A reference with a scheme is returned with its dot segments removed
// (RFC 3986 §5.2.2). A reference with an authority component ("//...") has
// no meaning under this decomposition and is an error.
func ResolveDIDReference(base, ref string) (string, error) {
	b, err := ParseDID(base)
	if err != nil {
		return "", fmt.Errorf("checks: base %q is not a DID: %w", base, err)
	}
	r := splitReference(ref)
	if r.hasScheme {
		out := r.scheme + ":" + removeDotSegments(r.path)
		return out + suffix(r.hasQuery, "?", r.query) + suffix(r.hasFrag, "#", r.fragment), nil
	}
	if r.hasAuthority {
		return "", fmt.Errorf("checks: reference %q has an authority component", ref)
	}
	var path, query string
	var hasQuery bool
	switch {
	case r.path == "":
		// Base.path is empty and Base.query undefined.
		path, query, hasQuery = "", r.query, r.hasQuery
	case strings.HasPrefix(r.path, "/"):
		path, query, hasQuery = removeDotSegments(r.path), r.query, r.hasQuery
	default:
		// RFC 3986 §5.2.3: the base has an authority and an empty path.
		path, query, hasQuery = removeDotSegments("/"+r.path), r.query, r.hasQuery
	}
	return "did:" + b.Method + ":" + b.MethodSpecificID + path + suffix(hasQuery, "?", query) + suffix(r.hasFrag, "#", r.fragment), nil
}

func suffix(present bool, sep, value string) string {
	if !present {
		return ""
	}
	return sep + value
}

// removeDotSegments is RFC 3986 §5.2.4.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			out = dropLastSegment(out)
		case in == "/..":
			in = "/"
			out = dropLastSegment(out)
		case in == "." || in == "..":
			in = ""
		default:
			end := strings.IndexByte(in[1:], '/')
			if end < 0 {
				out, in = append(out, in), ""
				continue
			}
			out, in = append(out, in[:end+1]), in[end+1:]
		}
	}
	return strings.Join(out, "")
}

func dropLastSegment(s []string) []string {
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}
