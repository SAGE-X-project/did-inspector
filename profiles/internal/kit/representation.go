package kit

import (
	"fmt"
	"slices"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// Produced is the result of producing a representation.
type Produced struct {
	Data      []byte
	MediaType string
	Err       error
	// Root is the parsed root of Data; ParseErr explains a parse failure.
	Root     core.Value
	ParseErr error
}

// Produce asks the producer for a representation of doc and parses it.
func Produce(p core.DocumentProducer, doc core.DocumentJSON, version string) Produced {
	var out Produced
	out.Data, out.MediaType, out.Err = p.Produce(doc, version)
	if out.Err == nil {
		out.Root, out.ParseErr = core.ParseJSON(out.Data)
	}
	return out
}

// Doc returns the produced root as a document; a root that is not an
// object returns false.
func (p Produced) Doc() (core.DocumentJSON, bool) {
	d, err := core.DocumentFromValue(p.Root)
	return d, p.Err == nil && p.ParseErr == nil && err == nil
}

// Consumed is the result of consuming a representation.
type Consumed struct {
	Doc  core.DocumentJSON
	Info core.ConsumeInfo
	Err  error
}

// Consume asks the consumer to consume data under a media type, requiring
// the version and every consumption rule.
func Consume(p core.DocumentConsumer, data []byte, mediaType, version string) Consumed {
	var out Consumed
	out.Doc, out.Info, out.Err = p.Consume(data, mediaType, version, true)
	return out
}

// Rule is one check of a representation case with the statements it
// judges.
type Rule struct {
	Statements []string
	Partial    string
	Check      func() (ok bool, expected, observed string)
}

// RunRules judges every rule; when the call the rules inspect failed, it
// records FAIL for every statement with the failure as the observed value.
func RunRules(input string, callErr error, rules []Rule) []core.Observation {
	var r Recorder
	for _, rule := range rules {
		if callErr != nil {
			r.Judge(rule.Statements, input, false, "the call succeeds on a conforming document", callErr.Error(), rule.Partial)
			continue
		}
		ok, exp, obs := rule.Check()
		r.Judge(rule.Statements, input, ok, exp, obs, rule.Partial)
	}
	return r.Observations()
}

// MembersKept reports whether every member of want, except the names in
// skip, is in got with an equal value.
func MembersKept(got, want core.DocumentJSON, skip ...string) (bool, string, string) {
	for _, m := range want.Members {
		if slices.Contains(skip, m.Name) {
			continue
		}
		v, ok := got.Get(m.Name)
		if !ok {
			return false, fmt.Sprintf("entry %q", m.Name), "no such entry"
		}
		if eq, at := checks.EqualJSON(v, m.Value); !eq {
			return false, fmt.Sprintf("entry %q = %s", m.Name, checks.Compact(m.Value)), fmt.Sprintf("%s (differs at %q)", checks.Compact(v), at)
		}
	}
	return true, "", ""
}

// ContextFirst reports whether a @context value is the context URL, or an
// array whose first item is the context URL.
func ContextFirst(v core.Value, url string) bool {
	switch v.Kind {
	case core.KindString:
		return v.Str == url
	case core.KindArray:
		return len(v.Array) > 0 && v.Array[0].Kind == core.KindString && v.Array[0].Str == url
	}
	return false
}

// MustDocument parses a document literal of the profile code.
func MustDocument(s string) core.DocumentJSON {
	d, err := core.ParseDocumentJSON([]byte(s))
	if err != nil {
		panic(err)
	}
	return d
}
