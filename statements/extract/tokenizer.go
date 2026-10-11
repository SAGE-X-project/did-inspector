package extract

import (
	"html"
	"strings"
)

// tokenType classifies a token produced by the tokenizer.
type tokenType int

const (
	textToken tokenType = iota
	startTagToken
	endTagToken
	selfClosingTagToken
	commentToken
	doctypeToken
)

// token is one lexical unit of an HTML document. Text tokens carry decoded
// character data; tag tokens carry a lower-case name and their attributes.
type token struct {
	typ   tokenType
	name  string
	attrs map[string]string
	data  string
}

// rawTextElements hold character data that is not parsed for tags.
var rawTextElements = map[string]bool{"script": true, "style": true}

// tokenizer is a small HTML tokenizer sufficient for the W3C publications the
// inspector pins: it recognises comments, doctype and processing declarations,
// start and end tags with quoted or unquoted attributes, and raw text in
// script and style elements. It does not build a tree.
type tokenizer struct {
	src     string
	pos     int
	pending *token
}

func newTokenizer(src string) *tokenizer {
	return &tokenizer{src: src}
}

// next returns the next token and false when the input is exhausted.
func (t *tokenizer) next() (token, bool) {
	if t.pending != nil {
		tok := *t.pending
		t.pending = nil
		return tok, true
	}
	if t.pos >= len(t.src) {
		return token{}, false
	}
	if t.src[t.pos] != '<' {
		return t.text(), true
	}
	rest := t.src[t.pos:]
	switch {
	case strings.HasPrefix(rest, "<!--"):
		return t.comment(), true
	case strings.HasPrefix(rest, "<!") || strings.HasPrefix(rest, "<?"):
		return t.declaration(), true
	case strings.HasPrefix(rest, "</") && len(rest) > 2 && isASCIIAlpha(rest[2]):
		return t.endTag(), true
	case len(rest) > 1 && isASCIIAlpha(rest[1]):
		return t.startTag(), true
	default:
		// A lone '<' is character data.
		t.pos++
		return token{typ: textToken, data: "<"}, true
	}
}

func (t *tokenizer) text() token {
	end := strings.IndexByte(t.src[t.pos:], '<')
	if end < 0 {
		end = len(t.src) - t.pos
	}
	raw := t.src[t.pos : t.pos+end]
	t.pos += end
	return token{typ: textToken, data: html.UnescapeString(raw)}
}

func (t *tokenizer) comment() token {
	body := t.src[t.pos+4:]
	end := strings.Index(body, "-->")
	if end < 0 {
		t.pos = len(t.src)
		return token{typ: commentToken, data: body}
	}
	t.pos += 4 + end + 3
	return token{typ: commentToken, data: body[:end]}
}

func (t *tokenizer) declaration() token {
	end := strings.IndexByte(t.src[t.pos:], '>')
	if end < 0 {
		data := t.src[t.pos+2:]
		t.pos = len(t.src)
		return token{typ: doctypeToken, data: data}
	}
	data := t.src[t.pos+2 : t.pos+end]
	t.pos += end + 1
	return token{typ: doctypeToken, data: data}
}

func (t *tokenizer) endTag() token {
	t.pos += 2
	name := t.readName()
	end := strings.IndexByte(t.src[t.pos:], '>')
	if end < 0 {
		t.pos = len(t.src)
	} else {
		t.pos += end + 1
	}
	return token{typ: endTagToken, name: name}
}

func (t *tokenizer) startTag() token {
	t.pos++
	name := t.readName()
	attrs := map[string]string{}
	typ := startTagToken
	for t.pos < len(t.src) {
		t.skipSpace()
		if t.pos >= len(t.src) {
			break
		}
		c := t.src[t.pos]
		if c == '>' {
			t.pos++
			break
		}
		if c == '/' {
			t.pos++
			if t.pos < len(t.src) && t.src[t.pos] == '>' {
				t.pos++
				typ = selfClosingTagToken
				break
			}
			continue
		}
		key, value := t.readAttr()
		if key == "" {
			// Unparseable byte inside a tag: skip it.
			t.pos++
			continue
		}
		if _, dup := attrs[key]; !dup {
			attrs[key] = value
		}
	}
	tok := token{typ: typ, name: name, attrs: attrs}
	if typ == startTagToken && rawTextElements[name] {
		t.skipRawText(name)
	}
	return tok
}

// skipRawText consumes the content of a raw text element and queues its end
// tag, so the caller sees start and end tags but no content. The end tag is
// "</" and the element name in any case, followed by white space, "/", ">"
// or the end of input.
func (t *tokenizer) skipRawText(name string) {
	for i := t.pos; i+2+len(name) <= len(t.src); i++ {
		if t.src[i] != '<' || t.src[i+1] != '/' || !strings.EqualFold(t.src[i+2:i+2+len(name)], name) {
			continue
		}
		j := i + 2 + len(name)
		if j == len(t.src) || isSpace(t.src[j]) || t.src[j] == '>' || t.src[j] == '/' {
			t.pos = i
			tok := t.endTag()
			t.pending = &tok
			return
		}
	}
	t.pos = len(t.src)
	t.pending = &token{typ: endTagToken, name: name}
}

func (t *tokenizer) readName() string {
	start := t.pos
	for t.pos < len(t.src) {
		c := t.src[t.pos]
		if isSpace(c) || c == '>' || c == '/' {
			break
		}
		t.pos++
	}
	return strings.ToLower(t.src[start:t.pos])
}

func (t *tokenizer) readAttr() (string, string) {
	start := t.pos
	for t.pos < len(t.src) {
		c := t.src[t.pos]
		if isSpace(c) || c == '>' || c == '/' || c == '=' {
			break
		}
		t.pos++
	}
	key := strings.ToLower(t.src[start:t.pos])
	t.skipSpace()
	if t.pos >= len(t.src) || t.src[t.pos] != '=' {
		return key, ""
	}
	t.pos++
	t.skipSpace()
	if t.pos >= len(t.src) {
		return key, ""
	}
	q := t.src[t.pos]
	if q == '"' || q == '\'' {
		end := strings.IndexByte(t.src[t.pos+1:], q)
		if end < 0 {
			v := t.src[t.pos+1:]
			t.pos = len(t.src)
			return key, html.UnescapeString(v)
		}
		v := t.src[t.pos+1 : t.pos+1+end]
		t.pos += end + 2
		return key, html.UnescapeString(v)
	}
	vs := t.pos
	for t.pos < len(t.src) && !isSpace(t.src[t.pos]) && t.src[t.pos] != '>' {
		t.pos++
	}
	return key, html.UnescapeString(t.src[vs:t.pos])
}

func (t *tokenizer) skipSpace() {
	for t.pos < len(t.src) && isSpace(t.src[t.pos]) {
		t.pos++
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
