package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Kind is the type of a JSON value.
type Kind uint8

// JSON value kinds.
const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

var kindNames = [...]string{"null", "boolean", "number", "string", "array", "object"}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("kind(%d)", k)
}

// Value is a JSON value that keeps object members in document order,
// including members whose names repeat, and numbers as their literal text,
// so that the inspector, not a decoder, decides what the content means.
type Value struct {
	Kind   Kind
	Bool   bool
	Number string
	Str    string
	Array  []Value
	Object []Member
}

// Member is one name/value pair of a JSON object.
type Member struct {
	Name  string
	Value Value
}

// Null returns the JSON null value.
func Null() Value { return Value{Kind: KindNull} }

// Bool returns a JSON boolean.
func Bool(b bool) Value { return Value{Kind: KindBool, Bool: b} }

// Number returns a JSON number with the given literal text.
func Number(literal string) Value { return Value{Kind: KindNumber, Number: literal} }

// String returns a JSON string.
func String(s string) Value { return Value{Kind: KindString, Str: s} }

// Array returns a JSON array.
func Array(items ...Value) Value { return Value{Kind: KindArray, Array: items} }

// Object returns a JSON object with members in the given order.
func Object(members ...Member) Value { return Value{Kind: KindObject, Object: members} }

// M returns a member; it keeps object literals short.
func M(name string, v Value) Member { return Member{Name: name, Value: v} }

// Get returns the value of the first member named name of an object.
func (v Value) Get(name string) (Value, bool) {
	for _, m := range v.Object {
		if m.Name == name {
			return m.Value, true
		}
	}
	return Value{}, false
}

// MarshalJSON writes the value with object members in order.
func (v Value) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := v.write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v Value) write(buf *bytes.Buffer) error {
	switch v.Kind {
	case KindNull:
		buf.WriteString("null")
	case KindBool:
		if v.Bool {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindNumber:
		if v.Number == "" || !isNumberLiteral(v.Number) || !json.Valid([]byte(v.Number)) {
			return fmt.Errorf("invalid JSON number literal %q", v.Number)
		}
		buf.WriteString(v.Number)
	case KindString:
		writeString(buf, v.Str)
	case KindArray:
		buf.WriteByte('[')
		for i, item := range v.Array {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := item.write(buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case KindObject:
		buf.WriteByte('{')
		for i, m := range v.Object {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, m.Name)
			buf.WriteByte(':')
			if err := m.Value.write(buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unknown JSON kind %d", v.Kind)
	}
	return nil
}

func isNumberLiteral(s string) bool {
	c := s[0]
	return c == '-' || (c >= '0' && c <= '9')
}

func writeString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	// Encoding a Go string cannot fail.
	_ = enc.Encode(s)
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

// UnmarshalJSON parses data into v, keeping member order and duplicates.
func (v *Value) UnmarshalJSON(data []byte) error {
	parsed, err := ParseJSON(data)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// maxDepth bounds nesting so that hostile input cannot exhaust the stack.
const maxDepth = 10000

// ErrInvalidUTF8 reports JSON text that is not valid UTF-8.
var ErrInvalidUTF8 = errors.New("JSON text is not valid UTF-8")

// ParseJSON parses exactly one JSON value. It rejects text that is not
// valid UTF-8 and trailing content after the value.
func ParseJSON(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return Value{}, ErrInvalidUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Value{}, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (Value, error) {
	if depth > maxDepth {
		return Value{}, errors.New("JSON nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Value{}, io.ErrUnexpectedEOF
		}
		return Value{}, err
	}
	switch t := tok.(type) {
	case nil:
		return Null(), nil
	case bool:
		return Bool(t), nil
	case json.Number:
		return Number(t.String()), nil
	case string:
		return String(t), nil
	case json.Delim:
		if t == '[' {
			return parseArray(dec, depth)
		}
		return parseObject(dec, depth)
	}
	return Value{}, fmt.Errorf("unexpected JSON token %v", tok)
}

func parseArray(dec *json.Decoder, depth int) (Value, error) {
	items := []Value{}
	for dec.More() {
		item, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		items = append(items, item)
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, err
	}
	return Array(items...), nil
}

func parseObject(dec *json.Decoder, depth int) (Value, error) {
	members := []Member{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return Value{}, err
		}
		name, ok := tok.(string)
		if !ok {
			return Value{}, fmt.Errorf("object member name is %v, not a string", tok)
		}
		val, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		members = append(members, Member{Name: name, Value: val})
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, err
	}
	return Object(members...), nil
}

// DocumentJSON is the inspector's neutral form of a DID document or a
// metadata structure: a JSON object that keeps its members in order,
// including repeated names, so that duplicates can be detected.
type DocumentJSON struct {
	Members []Member
}

// NewDocument returns a document with the given members.
func NewDocument(members ...Member) DocumentJSON {
	return DocumentJSON{Members: members}
}

// ParseDocumentJSON parses data, which must be a JSON object.
func ParseDocumentJSON(data []byte) (DocumentJSON, error) {
	v, err := ParseJSON(data)
	if err != nil {
		return DocumentJSON{}, err
	}
	return DocumentFromValue(v)
}

// DocumentFromValue converts an object value into a document.
func DocumentFromValue(v Value) (DocumentJSON, error) {
	if v.Kind != KindObject {
		return DocumentJSON{}, fmt.Errorf("JSON value is a %s, not an object", v.Kind)
	}
	return DocumentJSON{Members: v.Object}, nil
}

// Value returns the document as an object value.
func (d DocumentJSON) Value() Value {
	members := d.Members
	if members == nil {
		members = []Member{}
	}
	return Object(members...)
}

// Get returns the value of the first member named name.
func (d DocumentJSON) Get(name string) (Value, bool) {
	return d.Value().Get(name)
}

// Names returns the member names in order, including repeats.
func (d DocumentJSON) Names() []string {
	names := make([]string, len(d.Members))
	for i, m := range d.Members {
		names[i] = m.Name
	}
	return names
}

// Len returns the number of members, including repeats.
func (d DocumentJSON) Len() int {
	return len(d.Members)
}

// MarshalJSON writes the document with its members in order.
func (d DocumentJSON) MarshalJSON() ([]byte, error) {
	return d.Value().MarshalJSON()
}

// UnmarshalJSON parses an object, keeping member order and duplicates.
func (d *DocumentJSON) UnmarshalJSON(data []byte) error {
	parsed, err := ParseDocumentJSON(data)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
