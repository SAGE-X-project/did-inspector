package checks

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// EqualJSON reports whether two JSON values hold the same data under the
// data model of DID Core 1.0 §4 and DID 1.1 §4, and, when they do not, the
// JSON Pointer of the first difference.
//
// Member order is not significant: the data model's maps are ordered, but
// both specifications say that "ordering of a map or set is not important"
// unless stated otherwise, and JSON consumption guarantees no insertion
// order. Array order is significant. A number keeps its data type: a JSON
// number without a decimal or fractional component is an integer, one with
// either is a double (DID 1.1 §6.2), so 1 and 1.0 differ while 1.5 and
// 1.50 are equal.
func EqualJSON(a, b core.Value) (bool, string) {
	return equalAt(a, b, "")
}

func equalAt(a, b core.Value, ptr string) (bool, string) {
	if a.Kind != b.Kind {
		return false, ptr
	}
	switch a.Kind {
	case core.KindBool:
		return a.Bool == b.Bool, ptr
	case core.KindString:
		return a.Str == b.Str, ptr
	case core.KindNumber:
		return equalNumber(a.Number, b.Number), ptr
	case core.KindArray:
		if len(a.Array) != len(b.Array) {
			return false, ptr
		}
		for i := range a.Array {
			if ok, at := equalAt(a.Array[i], b.Array[i], ptr+"/"+strconv.Itoa(i)); !ok {
				return false, at
			}
		}
		return true, ""
	case core.KindObject:
		return equalObject(a.Object, b.Object, ptr)
	}
	return true, ""
}

func equalObject(a, b []core.Member, ptr string) (bool, string) {
	if len(a) != len(b) {
		return false, ptr
	}
	used := make([]bool, len(b))
	for _, m := range a {
		at := ptr + "/" + escapePointer(m.Name)
		j := -1
		for k, n := range b {
			if !used[k] && n.Name == m.Name {
				j = k
				break
			}
		}
		if j < 0 {
			return false, at
		}
		used[j] = true
		if ok, diff := equalAt(m.Value, b[j].Value, at); !ok {
			return false, diff
		}
	}
	return true, ""
}

func isInteger(literal string) bool {
	return !strings.ContainsAny(literal, ".eE")
}

func equalNumber(a, b string) bool {
	if isInteger(a) != isInteger(b) {
		return false
	}
	x, okA := new(big.Float).SetString(a)
	y, okB := new(big.Float).SetString(b)
	return okA && okB && x.Cmp(y) == 0
}

// ContainsJSON reports whether every member of want is a member of got with
// an equal value, and, when not, the name of the first member that is
// missing or different.
func ContainsJSON(got, want core.DocumentJSON) (bool, string) {
	for _, m := range want.Members {
		v, ok := got.Get(m.Name)
		if !ok {
			return false, m.Name
		}
		if eq, _ := EqualJSON(v, m.Value); !eq {
			return false, m.Name
		}
	}
	return true, ""
}

// Compact returns the JSON text of v, or a description of why it has none.
func Compact(v core.Value) string {
	data, err := v.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("<unprintable: %v>", err)
	}
	return string(data)
}
