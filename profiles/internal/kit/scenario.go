package kit

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// ScenarioFile is the format of testdata/resolution.json and
// testdata/dereferencing.json: calls of a resolution or dereferencing
// function with DIDs of the fixture method, and the results the
// specification requires.
type ScenarioFile struct {
	Scenarios []Scenario `json:"scenarios"`
	// Probes are further calls whose results only the invariant cases
	// judge: inputs for which the specification requires no particular
	// result but constrains the format of whatever comes back.
	Probes []Probe `json:"probes,omitempty"`
}

// Probe is a call without expectations of its own.
type Probe struct {
	Note     string         `json:"note"`
	Function string         `json:"function"`
	Input    string         `json:"input"`
	Options  map[string]any `json:"options"`
}

// calls returns the scenarios followed by the probes, as scenarios.
func (f ScenarioFile) calls() []Scenario {
	out := append([]Scenario{}, f.Scenarios...)
	for _, p := range f.Probes {
		out = append(out, Scenario{Case: "probe", Note: p.Note, Function: p.Function, Input: p.Input, Options: p.Options})
	}
	return out
}

// Scenario becomes one case.
type Scenario struct {
	// Case is the case id suffix.
	Case string `json:"case"`
	Note string `json:"note"`
	// Function is one of the Fn constants.
	Function string `json:"function"`
	// Input is the DID or DID URL and Options the options passed.
	Input   string         `json:"input"`
	Options map[string]any `json:"options"`
	// UnsupportedIf are error codes with which the subject declines an
	// optional feature the scenario uses; the scenario's statements are then
	// NOT_SUPPORTED, not FAIL.
	UnsupportedIf []string `json:"unsupportedIf,omitempty"`
	// NotApplicableIfSuccess marks scenarios whose input the subject may
	// legitimately dereference through a method or extension the inspector
	// does not know; a successful result is then NOT_APPLICABLE.
	NotApplicableIfSuccess bool `json:"notApplicableIfSuccess,omitempty"`
	// Expect are the checks, each with the statements it judges.
	Expect []Expectation `json:"expect"`
}

// Expectation is one check of the outcome.
type Expectation struct {
	// Check names a function of Checks.
	Check string `json:"check"`
	// Value is the check's argument.
	Value json.RawMessage `json:"value,omitempty"`
	// Statements are the statements the check judges.
	Statements []string `json:"statements"`
	// Partial says what the check does not judge of its statements.
	Partial string `json:"partial,omitempty"`
}

// Statements returns the statements of all expectations without repeats.
func (sc Scenario) Statements() []string {
	lists := make([][]string, len(sc.Expect))
	for i, e := range sc.Expect {
		lists[i] = e.Statements
	}
	return Union(lists...)
}

// CheckFunc judges an outcome against an expectation's value. It returns
// whether the outcome conforms, and otherwise the expected and observed
// values.
type CheckFunc func(o Outcome, value json.RawMessage) (ok bool, expected, observed string)

// Checks are the expectation checks scenarios can name.
var Checks = map[string]CheckFunc{
	"success":              checkSuccess,
	"successOrErrorCode":   checkSuccessOrErrorCode,
	"resourceEquals":       checkResourceEquals,
	"noError":              checkNoError,
	"errorPresent":         checkErrorPresent,
	"errorCode":            checkErrorCode,
	"metadataNotEmpty":     checkMetadataNotEmpty,
	"noContent":            checkNoContent,
	"contentMetadataEmpty": checkContentMetadataEmpty,
	"documentId":           checkDocumentID,
	"documentHas":          checkDocumentHas,
	"documentEquals":       checkDocumentEquals,
	"serviceIds":           checkServiceIDs,
	"deactivated":          checkDeactivated,
	"contentMetadataHas":   checkContentMetadataHas,
	"contentType":          checkContentType,
	"contentTypeAbsent":    checkContentTypeAbsent,
	"contentTypeAnywhere":  checkContentTypeAnywhere,
	"uriList":              checkURIList,
	"streamIsJSONObject":   checkStreamIsJSONObject,
}

// ScenarioCases returns one case per scenario. Every scenario resolves DIDs
// of the fixture method, so its case loads the registry first.
func ScenarioCases(profile, area string, reg *fixtures.Registry, f ScenarioFile) []core.Case {
	out := make([]core.Case, 0, len(f.Scenarios))
	for _, sc := range f.Scenarios {
		cp, _ := FunctionCapability(sc.Function)
		sts := sc.Statements()
		out = append(out, core.Case{
			ID:         profile + "/" + area + "/" + sc.Case,
			Profile:    profile,
			Statements: sts,
			Needs:      []core.Capability{core.CapFixtureMethod, cp},
			Run: RegistryCase(reg, sts, func(ctx context.Context, s core.Subject) []core.Observation {
				return JudgeScenario(sc, Call(ctx, s, sc.Function, sc.Input, CloneOptions(sc.Options)))
			}),
		})
	}
	return out
}

// CloneOptions returns a copy of the options, so that a subject cannot
// change a scenario's fixture.
func CloneOptions(opts map[string]any) map[string]any {
	out := make(map[string]any, len(opts))
	for k, v := range opts {
		out[k] = v
	}
	return out
}

// JudgeScenario turns an outcome into observations, one per statement of
// each expectation.
func JudgeScenario(sc Scenario, o Outcome) []core.Observation {
	var r Recorder
	input := describeCall(sc)
	if o.Err != nil {
		r.All(sc.Statements(), core.Error, input, "the subject returned no result: "+o.Err.Error())
		return r.Observations()
	}
	if code := o.ErrorCode(); code != "" && slices.Contains(sc.UnsupportedIf, code) {
		r.All(sc.Statements(), core.NotSupported, input, "the subject declined an optional feature the scenario uses: "+code)
		return r.Observations()
	}
	if sc.NotApplicableIfSuccess && o.Succeeded() {
		r.All(sc.Statements(), core.NotApplicable, input, "the subject dereferenced the input through a method or extension the inspector does not know")
		return r.Observations()
	}
	for _, e := range sc.Expect {
		check, ok := Checks[e.Check]
		if !ok {
			r.All(e.Statements, core.Error, input, "unknown check "+e.Check)
			continue
		}
		pass, exp, obs := check(o, e.Value)
		if !pass && obs == "" {
			obs = o.Summary()
		}
		r.Judge(e.Statements, input, pass, e.Check+": "+exp, obs, e.Partial)
	}
	return r.Observations()
}

func describeCall(sc Scenario) string {
	opts, _ := json.Marshal(sc.Options)
	return fmt.Sprintf("%s(%s, %s)", sc.Function, sc.Input, opts)
}

// stringsValue decodes a check value that is a string or a list of strings.
func stringsValue(v json.RawMessage) []string {
	var one string
	if json.Unmarshal(v, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(v, &many)
	return many
}

func objectValue(v json.RawMessage) core.DocumentJSON {
	var d core.DocumentJSON
	_ = json.Unmarshal(v, &d)
	return d
}

func checkSuccess(o Outcome, _ json.RawMessage) (bool, string, string) {
	return o.Succeeded(), "a result with content and no error", ""
}

func checkSuccessOrErrorCode(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	return o.Succeeded() || slices.Contains(want, o.ErrorCode()), "a result with content, or error " + strings.Join(want, " or "), ""
}

func checkNoError(o Outcome, _ json.RawMessage) (bool, string, string) {
	return !o.Failed(), "no error property", ""
}

func checkErrorPresent(o Outcome, _ json.RawMessage) (bool, string, string) {
	return o.Failed(), "an error property", ""
}

func checkErrorCode(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	got := o.ErrorCode()
	return slices.Contains(want, got), "error " + strings.Join(want, " or "), "error " + fmt.Sprintf("%q", got)
}

func checkMetadataNotEmpty(o Outcome, _ json.RawMessage) (bool, string, string) {
	return o.Metadata.Len() > 0, "non-empty metadata", ""
}

func checkNoContent(o Outcome, _ json.RawMessage) (bool, string, string) {
	return !o.HasContent(), "no document and an empty stream", ""
}

func checkContentMetadataEmpty(o Outcome, _ json.RawMessage) (bool, string, string) {
	return o.ContentMetadata.Len() == 0, "an empty metadata structure", "content metadata " + checks.Compact(o.ContentMetadata.Value())
}

func checkDocumentID(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)[0]
	d, why := o.Doc()
	if why != "" {
		return false, "a document with id " + want, why
	}
	got, _ := StringMember(d, "id")
	return got == want, "id " + want, "id " + fmt.Sprintf("%q", got)
}

// withoutContext drops the @context member, which an adapter may keep in
// the abstract document or in the representation-specific entries.
func withoutContext(d core.DocumentJSON) core.DocumentJSON {
	var out core.DocumentJSON
	for _, m := range d.Members {
		if m.Name != "@context" {
			out.Members = append(out.Members, m)
		}
	}
	return out
}

func checkDocumentHas(o Outcome, v json.RawMessage) (bool, string, string) {
	want := objectValue(v)
	d, why := o.Doc()
	if why != "" {
		return false, "a document with " + checks.Compact(want.Value()), why
	}
	ok, name := checks.ContainsJSON(d, want)
	got, _ := d.Get(name)
	return ok, "member " + name + " as in " + checks.Compact(want.Value()), "member " + name + " " + checks.Compact(got)
}

func checkDocumentEquals(o Outcome, v json.RawMessage) (bool, string, string) {
	want := withoutContext(objectValue(v))
	d, why := o.Doc()
	if why != "" {
		return false, checks.Compact(want.Value()), why
	}
	got := withoutContext(d)
	ok, at := checks.EqualJSON(got.Value(), want.Value())
	return ok, checks.Compact(want.Value()) + " (ignoring @context)", fmt.Sprintf("%s (first difference at %q)", checks.Compact(got.Value()), at)
}

func checkServiceIDs(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	d, why := o.Doc()
	if why != "" {
		return false, "services " + strings.Join(want, ", "), why
	}
	base := baseDID(o.Input)
	var got []string
	if svc, ok := d.Get("service"); ok {
		for _, s := range svc.Array {
			id, _ := s.Get("id")
			got = append(got, absolute(base, id.Str))
		}
	}
	return slices.Equal(got, want), "services " + fmt.Sprintf("%q", want), "services " + fmt.Sprintf("%q", got)
}

// baseDID returns the DID of a DID URL: the part before any path, query or
// fragment.
func baseDID(didURL string) string {
	if u, err := checks.ParseDIDURL(didURL); err == nil {
		return u.DID.DID
	}
	return didURL
}

// absolute resolves a fragment-only relative DID URL against the DID, as
// RFC 3986 §5.2 does for a reference that consists of a fragment; other
// values are returned unchanged.
func absolute(did, ref string) string {
	if strings.HasPrefix(ref, "#") {
		return did + ref
	}
	return ref
}

// checkResourceEquals compares a returned resource, such as a verification
// method, with the expected object, ignoring @context and resolving a
// fragment-only relative id against the DID of the input.
func checkResourceEquals(o Outcome, v json.RawMessage) (bool, string, string) {
	base := baseDID(o.Input)
	want := absoluteID(base, withoutContext(objectValue(v)))
	d, why := o.Doc()
	if why != "" {
		return false, checks.Compact(want.Value()), why
	}
	got := absoluteID(base, withoutContext(d))
	ok, at := checks.EqualJSON(got.Value(), want.Value())
	return ok, checks.Compact(want.Value()) + " (ignoring @context)", fmt.Sprintf("%s (first difference at %q)", checks.Compact(got.Value()), at)
}

func absoluteID(base string, d core.DocumentJSON) core.DocumentJSON {
	out := core.DocumentJSON{Members: make([]core.Member, len(d.Members))}
	for i, m := range d.Members {
		if m.Name == "id" && m.Value.Kind == core.KindString {
			m = core.M("id", core.String(absolute(base, m.Value.Str)))
		}
		out.Members[i] = m
	}
	return out
}

func checkDeactivated(o Outcome, v json.RawMessage) (bool, string, string) {
	want := string(v) == "true"
	got, ok := o.ContentMetadata.Get("deactivated")
	if !ok {
		return false, fmt.Sprintf("deactivated %v", want), "no deactivated property"
	}
	return got.Kind == core.KindBool && got.Bool == want, fmt.Sprintf("deactivated %v", want), "deactivated " + checks.Compact(got)
}

func checkContentMetadataHas(o Outcome, v json.RawMessage) (bool, string, string) {
	want := objectValue(v)
	ok, name := checks.ContainsJSON(o.ContentMetadata, want)
	return ok, "content metadata with " + checks.Compact(want.Value()), fmt.Sprintf("member %q missing or different in %s", name, checks.Compact(o.ContentMetadata.Value()))
}

func checkContentType(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	got, ok := StringMember(o.Metadata, "contentType")
	return ok && slices.Contains(want, checks.MediaTypeEssence(got)), "contentType " + strings.Join(want, " or "), fmt.Sprintf("contentType %q", got)
}

func checkContentTypeAbsent(o Outcome, _ json.RawMessage) (bool, string, string) {
	got, ok := o.Metadata.Get("contentType")
	return !ok, "no contentType property", "contentType " + checks.Compact(got)
}

func checkContentTypeAnywhere(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	for _, d := range []core.DocumentJSON{o.Metadata, o.ContentMetadata} {
		if got, ok := StringMember(d, "contentType"); ok && slices.Contains(want, checks.MediaTypeEssence(got)) {
			return true, "", ""
		}
	}
	return false, "contentType " + strings.Join(want, " or ") + " in either metadata structure", ""
}

func checkURIList(o Outcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	got, err := checks.ParseURIList(o.Stream)
	if err != nil {
		return false, "text/uri-list " + fmt.Sprintf("%q", want), err.Error()
	}
	return slices.Equal(got, want), "text/uri-list " + fmt.Sprintf("%q", want), fmt.Sprintf("%q", got)
}

func checkStreamIsJSONObject(o Outcome, _ json.RawMessage) (bool, string, string) {
	if len(o.Stream) == 0 {
		return false, "a byte stream of a JSON representation", "an empty stream"
	}
	_, err := core.ParseDocumentJSON(o.Stream)
	return err == nil, "a byte stream of a JSON representation", errText("not a JSON object", err)
}
