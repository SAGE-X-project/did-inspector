package checks

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// Duplicate is one member name that appears more than once in one object.
type Duplicate struct {
	// Pointer is the RFC 6901 JSON Pointer of the object.
	Pointer string
	// Name is the repeated member name.
	Name string
	// Count is how many times it appears.
	Count int
}

// DuplicateMembers returns every member name that repeats within an object
// of v, in document order of first repetition, with objects visited depth
// first.
func DuplicateMembers(v core.Value) []Duplicate {
	var out []Duplicate
	walkDuplicates(v, "", &out)
	return out
}

// DuplicateMembersInBytes parses data as JSON and returns its duplicate
// members.
func DuplicateMembersInBytes(data []byte) ([]Duplicate, error) {
	v, err := core.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	return DuplicateMembers(v), nil
}

func walkDuplicates(v core.Value, ptr string, out *[]Duplicate) {
	switch v.Kind {
	case core.KindArray:
		for i, item := range v.Array {
			walkDuplicates(item, ptr+"/"+strconv.Itoa(i), out)
		}
	case core.KindObject:
		counts := map[string]int{}
		var order []string
		for _, m := range v.Object {
			counts[m.Name]++
			if counts[m.Name] == 2 {
				order = append(order, m.Name)
			}
		}
		for _, name := range order {
			*out = append(*out, Duplicate{Pointer: ptr, Name: name, Count: counts[name]})
		}
		for _, m := range v.Object {
			walkDuplicates(m.Value, ptr+"/"+escapePointer(m.Name), out)
		}
	}
}

// escapePointer escapes a reference token per RFC 6901 §3.
func escapePointer(s string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}

// Datetime errors.
var (
	// ErrDatetimeSyntax: the string is not an XML Schema dateTime.
	ErrDatetimeSyntax = errors.New("not an XML Schema 1.1 dateTime")
	// ErrDatetimeNotUTC: the time zone is missing or not written "Z".
	ErrDatetimeNotUTC = errors.New("not normalized to UTC (time zone must be Z)")
	// ErrDatetimeFraction: the seconds have a fractional part.
	ErrDatetimeFraction = errors.New("has sub-second decimal precision")
	// ErrDatetimeEndOfDay: the time is 24:00:00, which normalizes to 00:00:00
	// of the next day.
	ErrDatetimeEndOfDay = errors.New("uses 24:00:00, which is not the normalized form")
)

// CheckDatetime checks that s is an XML Schema 1.1 dateTime normalized to
// UTC and without sub-second decimal precision, as DID Core 1.0 and DID 1.1
// require for datetime values (for example 2020-12-20T19:17:47Z) and DID
// Resolution requires for its timestamps.
//
// The lexical form is that of XML Schema 1.1 Part 2 §3.3.7:
// -?YYYY-MM-DDThh:mm:ss(.s+)?(Z|(+|-)hh:mm)?, with a year of four or more
// digits (no leading zero beyond four digits), a day valid for its month and
// year, and 24:00:00 allowed only as end of day. The normalized form the
// specifications require has the time zone written Z, no fractional seconds
// and no 24:00:00.
func CheckDatetime(s string) error {
	p, ok := lexDatetime(s)
	if !ok {
		return fmt.Errorf("%q: %w", s, ErrDatetimeSyntax)
	}
	switch {
	case p.zone != "Z":
		return fmt.Errorf("%q: %w", s, ErrDatetimeNotUTC)
	case p.fraction:
		return fmt.Errorf("%q: %w", s, ErrDatetimeFraction)
	case p.hour == 24:
		return fmt.Errorf("%q: %w", s, ErrDatetimeEndOfDay)
	}
	return nil
}

type datetimeParts struct {
	hour     int
	fraction bool
	zone     string
}

// lexDatetime matches the XML Schema 1.1 dateTime lexical space.
func lexDatetime(s string) (datetimeParts, bool) {
	var p datetimeParts
	i := 0
	if strings.HasPrefix(s, "-") {
		i++
	}
	ys := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	yearDigits := s[ys:i]
	if len(yearDigits) < 4 || (len(yearDigits) > 4 && yearDigits[0] == '0') {
		return p, false
	}
	year, err := strconv.ParseInt(yearDigits, 10, 64)
	if err != nil {
		return p, false
	}
	rest := s[i:]
	// -MM-DDThh:mm:ss is 15 characters.
	if len(rest) < 15 || rest[0] != '-' || rest[3] != '-' || rest[6] != 'T' || rest[9] != ':' || rest[12] != ':' {
		return p, false
	}
	month, ok1 := twoDigits(rest[1:3])
	day, ok2 := twoDigits(rest[4:6])
	hour, ok3 := twoDigits(rest[7:9])
	minute, ok4 := twoDigits(rest[10:12])
	second, ok5 := twoDigits(rest[13:15])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return p, false
	}
	if month < 1 || month > 12 || day < 1 || day > daysIn(year, month) || minute > 59 || second > 59 {
		return p, false
	}
	rest = rest[15:]
	if strings.HasPrefix(rest, ".") {
		j := 1
		for j < len(rest) && isDigit(rest[j]) {
			j++
		}
		if j == 1 {
			return p, false
		}
		p.fraction = true
		rest = rest[j:]
	}
	if hour > 24 || (hour == 24 && (minute != 0 || second != 0 || p.fraction)) {
		return p, false
	}
	if !validZone(rest) {
		return p, false
	}
	p.hour, p.zone = hour, rest
	return p, true
}

func twoDigits(s string) (int, bool) {
	if !isDigit(s[0]) || !isDigit(s[1]) {
		return 0, false
	}
	return int(s[0]-'0')*10 + int(s[1]-'0'), true
}

// validZone matches the optional timezoneFrag: Z, or (+|-)hh:mm with
// hh:mm at most 14:00.
func validZone(z string) bool {
	switch {
	case z == "" || z == "Z":
		return true
	case len(z) != 6 || (z[0] != '+' && z[0] != '-') || z[3] != ':':
		return false
	}
	h, ok1 := twoDigits(z[1:3])
	m, ok2 := twoDigits(z[4:6])
	if !ok1 || !ok2 || m > 59 {
		return false
	}
	return h < 14 || (h == 14 && m == 0)
}

// daysIn returns the number of days in a month of a year of XML Schema 1.1,
// where year 0000 exists and is a leap year.
func daysIn(year int64, month int) int {
	switch month {
	case 2:
		if year%400 == 0 || (year%4 == 0 && year%100 != 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}
