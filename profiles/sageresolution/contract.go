package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"reflect"
	"strconv"
	"strings"
)

type contractFixture struct {
	Name       string                `json:"name"`
	Record     sageprojection.Record `json:"record"`
	Request    ContractRequest       `json:"request"`
	ErrorType  string                `json:"error_type,omitempty"`
	Statements []string              `json:"statements"`
}

func contractIDs(names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = resolutionPrefix + n
	}
	return out
}
func contractFixtures(rows []sageprojection.Record) []contractFixture {
	var out []contractFixture
	add := func(name string, record int, q ContractRequest, typ string, ids []string) {
		out = append(out, contractFixture{name, rows[record], q, typ, ids})
	}
	for _, i := range []int{0, 1, 2, 3, 5} {
		for _, accept := range []string{"", "application/did"} {
			q := ContractRequest{Request: Request{Function: "dereference", Input: rows[i].DID, Accept: accept}}
			ids := contractIDs("dereferencing.1", "dereferencing.2", "dereferencing.4", "dereferencing.5", "dereferencing.6", "dereferencing.11", "dereferencing-algorithm-resource.12", "dereferencing-algorithm-resource.13", "dereferencing-algorithm-resource.14", "dereferencing-algorithm-resource.15")
			add(fmt.Sprintf("document-%d-%t", i, accept != ""), i, q, "", ids)
		}
	}
	for _, accept := range []string{"", "application/did"} {
		add(fmt.Sprintf("resolve-%t", accept != ""), 0, ContractRequest{Request: Request{Function: "resolve", Input: rows[0].DID, Accept: accept}}, "", contractIDs("resolving.2", "resolving.3"))
	}
	add("resolve-options", 0, ContractRequest{Request: Request{Function: "resolve", Input: rows[0].DID, Options: map[string]any{"noCache": true}}}, "", contractIDs("resolving.2", "resolving.3"))
	for _, key := range []string{"sign", "agree"} {
		add("fragment-"+key, 0, ContractRequest{Request: Request{Function: "dereference", Input: rows[0].DID + "#" + key}}, "", contractIDs("dereferencing.3", "dereferencing.2", "dereferencing.4", "dereferencing.5", "dereferencing.6", "dereferencing.11"))
	}
	add("authorized-sign", 0, ContractRequest{Request: Request{Function: "dereference", Input: rows[0].DID + "#sign", Relationship: "authentication"}}, "", contractIDs("dereferencing.3", "did-url-dereferencing-options.5"))
	errors := []struct {
		name, fn, input, rel, accept, typ string
		zero                              bool
	}{
		{"zero-resolve", "resolve", "", "", "", "INVALID_DID", true},
		{"zero-dereference", "dereference", "", "", "", "INVALID_DID_URL", true},
		{"missing-fragment", "dereference", rows[0].DID + "#unknown", "", "", "NOT_FOUND", false},
		{"wrong-purpose", "dereference", rows[0].DID + "#agree", "authentication", "", "https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD", false},
		{"no-method", "dereference", rows[0].DID, "authentication", "", "https://w3id.org/security#INVALID_VERIFICATION_METHOD", false},
		{"unsupported-media", "resolve", rows[0].DID, "", "text/html", "FEATURE_NOT_SUPPORTED", false},
		{"unsupported-deref-media", "dereference", rows[0].DID, "", "text/html", "REPRESENTATION_NOT_SUPPORTED", false},
	}
	for _, s := range errors {
		typ := s.typ
		if !strings.Contains(typ, "://") {
			typ = "https://www.w3.org/ns/did#" + typ
		}
		q := ContractRequest{Request: Request{Function: s.fn, Input: s.input, Accept: s.accept, Relationship: s.rel}, Zero: s.zero}
		ids := contractIDs("errors.1", "errors.4", "errors.5")
		if s.fn == "resolve" {
			ids = append(ids, contractIDs("resolving.2", "resolving.3")...)
		} else {
			ids = append(ids, contractIDs("dereferencing.2", "dereferencing.4", "dereferencing.5", "dereferencing.6", "dereferencing.7")...)
		}
		if s.name == "zero-dereference" {
			ids = append(ids, contractIDs("dereferencing-algorithm-resource.1", "dereferencing-algorithm-resource.2", "dereferencing-algorithm-resource.3", "dereferencing-algorithm-resource.4")...)
		}
		if s.name == "wrong-purpose" || s.name == "no-method" {
			ids = append(ids, resolutionPrefix+"did-url-dereferencing-options.5")
		}
		if s.name == "missing-fragment" {
			ids = append(ids, resolutionPrefix+"dereferencing.3")
		}
		if s.name == "unsupported-media" {
			ids = append(ids, resolutionPrefix+"errors.7")
		}
		add(s.name, 0, q, typ, ids)
	}
	return out
}
func contractCapture(f contractFixture, out ContractResult) core.Verdict {
	if out.Operation != "github.com/sage-x-project/did-go/advanced/sage.Resolver."+map[string]string{"resolve": "ResolveWithCode", "dereference": "DereferenceWithCode"}[f.Request.Request.Function] || out.CaptureError != "" || out.Result.Native != nil || out.Result.Exchange != nil {
		return core.Error
	}
	var input string
	identifier, e := core.ParseJSON(out.Identifier)
	if e != nil || identifier.Kind != core.KindString {
		return core.Error
	}
	if _, e := parse(out.Options); e != nil {
		return core.Error
	}
	var options map[string]any
	if json.Unmarshal(out.Identifier, &input) != nil || json.Unmarshal(out.Options, &options) != nil || options == nil {
		return core.Error
	}
	q := f.Request.Request
	expected := map[string]any{}
	for k, v := range q.Options {
		expected[k] = v
	}
	if q.Accept != "" {
		expected["accept"] = q.Accept
	}
	if q.Relationship != "" {
		expected["verificationRelationship"] = q.Relationship
	}
	if input != q.Input || !reflect.DeepEqual(options, expected) {
		return core.Error
	}
	serializers := out.Metadata
	if serializers.Resolution.Serializer != "github.com/sage-x-project/did-go/resolution.ResolutionMetadata.MarshalJSON" || serializers.Document.Serializer != "github.com/sage-x-project/did-go/document.Metadata.MarshalJSON" || serializers.Resolution.Error != "" || serializers.Document.Error != "" {
		return core.Error
	}
	for _, pair := range [][2][]byte{{serializers.Resolution.Bytes, out.Result.Metadata}, {serializers.Document.Bytes, out.Result.ContentMetadata}} {
		a, e := parse(pair[0])
		if e != nil {
			return core.Error
		}
		b, e := parse(pair[1])
		if e != nil {
			return core.Error
		}
		if !equalObserved(a.Value(), b.Value(), "metadata") {
			return core.Fail
		}
	}

	return core.Pass
}
func contractOutcome(f contractFixture, o ContractResult) core.Verdict {
	if v := contractCapture(f, o); v != core.Pass {
		return v
	}
	md, _ := parse(o.Result.Metadata)
	cm, _ := parse(o.Result.ContentMetadata)
	if f.ErrorType != "" {
		if !nativeErrorDescriptor(md) || errorName(md) != f.ErrorType || !nativeNullDocument(o.Result) || cm.Len() != 0 || o.Reference != nil {
			return core.Fail
		}
		if f.Request.Request.Function == "dereference" {
			raw, e := core.ParseJSON(o.Result.Raw)
			if e != nil || raw.Kind != core.KindNull {
				return core.Fail
			}
		}
		return core.Pass
	}
	if _, ok := md.Get("error"); ok {
		return core.Fail
	}
	q := f.Request.Request
	if !o.Result.HasContent || o.Result.ReturnedID != q.Input {
		return core.Fail
	}
	if q.Function == "resolve" {
		if o.Result.ContentKind != "document" || !checks.IsDID(q.Input) || o.Reference != nil {
			return core.Fail
		}
		return core.Pass
	}
	ref := o.Reference
	if ref == nil || !ref.HasContent || ref.ReturnedID != f.Record.DID || ref.ContentKind != "document" || ref.Native != nil || ref.Exchange != nil {
		return core.Error
	}
	refMD, e := parse(ref.Metadata)
	if e != nil {
		return core.Error
	}
	if _, ok := refMD.Get("error"); ok {
		return core.Error
	}
	a, e := parse(ref.Snapshot)
	if e != nil {
		return core.Error
	}
	id, _ := a.Get("id")
	if id.Kind != core.KindString || id.Str != f.Record.DID {
		return core.Fail
	}
	b, e := parse(o.Result.Snapshot)
	if e != nil {
		return core.Error
	}
	if strings.Contains(q.Input, "#") {
		if o.Result.ContentKind != "verification-method" {
			return core.Fail
		}
		methods, ok := a.Get("verificationMethod")
		if !ok || methods.Kind != core.KindArray {
			return core.Error
		}
		matched := false
		for _, m := range methods.Array {
			id, _ := m.Get("id")
			if id.Str == q.Input && equalObserved(m, b.Value(), "method") {
				matched = true
			}
		}
		if !matched {
			return core.Fail
		}
		if q.Relationship != "" {
			rels, ok := a.Get(q.Relationship)
			if !ok || rels.Kind != core.KindArray {
				return core.Fail
			}
			found := false
			for _, v := range rels.Array {
				if v.Str == q.Input {
					found = true
				}
			}
			if !found {
				return core.Fail
			}
		}
	} else {
		if o.Result.ContentKind != "document" || !equalObserved(a.Value(), b.Value(), "document") {
			return core.Fail
		}
		c, e := parse(ref.ContentMetadata)
		if e != nil {
			return core.Error
		}
		d, _ := parse(o.Result.ContentMetadata)
		if !equalObserved(c.Value(), d.Value(), "metadata") {
			return core.Fail
		}
	}
	return core.Pass
}
func contractProblemAttribution(o ContractResult) core.Verdict {
	if o.ProblemSerializer != "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)" {
		return core.Error
	}
	p, e := parse(o.Problem)
	if e != nil {
		return core.Error
	}
	md, e := parse(o.Result.Metadata)
	if e != nil {
		return core.Error
	}
	original, _ := md.Get("error")
	if !equalObserved(p.Value(), original, "metadata") {
		return core.Fail
	}
	return core.Pass
}
func contractProblem(o ContractResult) core.Verdict {
	if v := contractProblemAttribution(o); v != core.Pass {
		return v
	}
	p, _ := parse(o.Problem)

	typ, _ := p.Get("type")
	if typ.Kind != core.KindString || !checks.IsAbsoluteURI(typ.Str) {
		return core.Fail
	}
	for _, k := range []string{"title", "detail", "instance"} {
		if v, ok := p.Get(k); ok && v.Kind != core.KindString {
			return core.Fail
		}
	}
	if v, ok := p.Get("status"); ok {
		number, e := strconv.Atoi(v.Number)
		if v.Kind != core.KindNumber || e != nil || number < 100 || number > 599 {
			return core.Fail
		}
	}
	if v, ok := p.Get("instance"); ok && !checks.IsAbsoluteURI(v.Str) {
		return core.NotSupported
	}

	return core.Pass
}

// Human recommendations are independent of mandatory native refusal. These
// fixture-specific strings have a reviewed meaning; nonempty arbitrary prose
// alone is not evidence of a useful explanation.
func contractAdvisory(f contractFixture, o ContractResult, id string) core.Verdict {
	p, e := parse(o.Problem)
	if e != nil {
		return core.Error
	}
	field := "detail"
	if id == resolutionPrefix+"errors.4" {
		field = "title"
	}
	v, ok := p.Get(field)
	if !ok || v.Kind != core.KindString || strings.TrimSpace(v.Str) == "" {
		return core.Fail
	}
	titles := map[string]string{"zero-resolve": "Invalid DID", "zero-dereference": "Invalid DID URL", "missing-fragment": "Not found", "wrong-purpose": "Invalid relationship for verification method", "no-method": "Invalid verification method", "unsupported-media": "Feature not supported", "unsupported-deref-media": "Representation not supported"}
	details := map[string]string{"zero-resolve": "the DID is empty", "zero-dereference": "a DID URL to dereference is absolute", "missing-fragment": "no part of the DID document has the id " + f.Request.Request.Input, "wrong-purpose": f.Request.Request.Input + " is not in authentication", "no-method": "the DID URL has no fragment, so it does not dereference to a verification method", "unsupported-media": "no representation acceptable to \"text/html\" can be produced", "unsupported-deref-media": "no DID document representation is acceptable to text/html"}
	expected := details[f.Name]
	if field == "title" {
		expected = titles[f.Name]
	}
	if v.Str == expected && expected != "" {
		return core.Pass
	}
	return core.NotSupported
}
func contractClause(f contractFixture, o ContractResult, id string) core.Verdict {
	if v := contractCapture(f, o); v != core.Pass {
		return v
	}
	md, _ := parse(o.Result.Metadata)
	cm, _ := parse(o.Result.ContentMetadata)
	_, failed := md.Get("error")
	pass := true
	switch id {
	case resolutionPrefix + "resolving.2", resolutionPrefix + "dereferencing.4":
		if f.Request.Zero {
			pass = nativeErrorDescriptor(md) && !o.Result.HasContent
		} else if f.Request.Request.Function == "resolve" {
			pass = checks.IsDID(f.Request.Request.Input)
		} else {
			pass = checks.IsDIDURL(f.Request.Request.Input)
		}
	case resolutionPrefix + "resolving.3", resolutionPrefix + "dereferencing.5", resolutionPrefix + "dereferencing.2", resolutionPrefix + "dereferencing-algorithm-resource.13":
		// Selected input/options and metadata serialization is checked by capture.
	case resolutionPrefix + "dereferencing.6":
		pass = f.ErrorType == "" || md.Len() > 0
	case resolutionPrefix + "dereferencing.7":
		pass = nativeErrorDescriptor(md)
	case resolutionPrefix + "dereferencing.11":
		if failed || !o.Result.HasContent {
			return core.NotApplicable
		}
	case resolutionPrefix + "dereferencing-algorithm-resource.2":
		pass = nativeErrorDescriptor(md) && errorName(md) == "https://www.w3.org/ns/did#INVALID_DID_URL"
	case resolutionPrefix + "dereferencing-algorithm-resource.3":
		value, e := core.ParseJSON(o.Result.Raw)
		pass = nativeNullDocument(o.Result) && e == nil && value.Kind == core.KindNull
	case resolutionPrefix + "dereferencing-algorithm-resource.4":
		pass = cm.Len() == 0
	case resolutionPrefix + "did-url-dereferencing-options.5", resolutionPrefix + "dereferencing.3":
		if f.ErrorType != "" {
			pass = nativeErrorDescriptor(md) && !o.Result.HasContent
		} else {
			return contractOutcome(f, o)
		}
	case resolutionPrefix + "dereferencing.1":
		doc, e := parse(o.Result.Snapshot)
		id, _ := doc.Get("id")
		pass = e == nil && o.Result.HasContent && o.Result.ContentKind == "document" && id.Str == f.Record.DID && o.Result.ReturnedID == f.Record.DID && !failed
	case resolutionPrefix + "dereferencing-algorithm-resource.14", resolutionPrefix + "dereferencing-algorithm-resource.15":
		ref := o.Reference
		if ref == nil || !ref.HasContent || ref.ReturnedID != f.Record.DID || ref.ContentKind != "document" || ref.Native != nil || ref.Exchange != nil {
			return core.Error
		}
		referenceMD, e := parse(ref.Metadata)
		if e != nil {
			return core.Error
		}
		if _, ok := referenceMD.Get("error"); ok {
			return core.Error
		}
		d, e := parse(ref.Snapshot)
		if e != nil {
			return core.Error
		}
		identifier, _ := d.Get("id")
		if identifier.Str != f.Record.DID {
			return core.Fail
		}
		if id == resolutionPrefix+"dereferencing-algorithm-resource.14" {
			actual, e := parse(o.Result.Snapshot)
			if e != nil {
				return core.Error
			}
			pass = o.Result.HasContent && o.Result.ContentKind == "document" && o.Result.ReturnedID == f.Record.DID && equalObserved(d.Value(), actual.Value(), "document")
		} else {
			dm, e := parse(ref.ContentMetadata)
			if e != nil {
				return core.Error
			}
			pass = equalObserved(dm.Value(), cm.Value(), "metadata")
		}
	case resolutionPrefix + "dereferencing-algorithm-resource.1", resolutionPrefix + "dereferencing-algorithm-resource.12":
		return contractOutcome(f, o)
	case resolutionPrefix + "errors.1":
		return contractProblem(o)
	case resolutionPrefix + "errors.4", resolutionPrefix + "errors.5", resolutionPrefix + "errors.7":
		if v := contractProblemAttribution(o); v != core.Pass {
			return v
		}
		if id == resolutionPrefix+"errors.7" && errorName(md) != "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED" {
			return core.NotApplicable
		}
		return contractAdvisory(f, o, id)
	default:
		return core.Error
	}
	if !pass {
		return core.Fail
	}
	return core.Pass
}
func judgeContract(f contractFixture, out ContractResult, input string) []core.Observation {
	raw, _ := json.Marshal(out)
	obs := unavailable(f.Statements, core.Error, "Fresh typed SAGE resolve/dereference call with actual pre-call identifier/options and original direct metadata serializers. Zero inputs reach the actual entry. Selected input serialization, metadata presence, mandatory refusal, explicitly prescribed error types, document/method comparisons, RFC problem shape and each human recommendation have separate clause verdicts. Reference is a separate fresh resolve call, not proof of an internal invocation. JSON serializability covers selected identifier/options and two metadata outputs, excluding contentStream. Typed input/grammar evidence does not cover every malformed string, extension or DID method. No deployed authority, history, Source ownership, all-document conformance or full recursive fragment walk is claimed.")
	for i := range obs {
		obs[i].Verdict = contractClause(f, out, obs[i].Statement)
		obs[i].Input = input
		obs[i].Observed = string(raw)
		obs[i].Expected = "Clause-specific typed input, metadata, selected result or separately reviewed native problem explanation"
	}
	return obs
}

func appendContractCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range contractFixtures(rows) {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-contract-" + f.Name, Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(ContractSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no actual typed native entry observer", string(input), ContractResult{})
			}
			out, e := s.InspectContract(ctx, f.Record, f.Request)
			if e != nil {
				return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
			}
			return judgeContract(f, out, string(input))
		}})
	}
}
