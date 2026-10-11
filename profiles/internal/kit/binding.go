package kit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// BindingFile is the format of testdata/binding.json: requests of the
// HTTP(S) binding of DID Resolution §12.1 for DIDs and DID URLs of the
// fixture method, and what the specification requires of the responses.
type BindingFile struct {
	Exchanges []BindingScenario `json:"exchanges"`
	// Probes are further requests whose responses only the invariant case
	// judges.
	Probes []BindingProbe `json:"probes,omitempty"`
}

// BindingRequest describes one request of the binding.
type BindingRequest struct {
	// Function is FnResolve or FnDereference.
	Function string `json:"function"`
	// Method is GET (the default) or POST.
	Method string `json:"method,omitempty"`
	// Input is the DID or DID URL.
	Input string `json:"input"`
	// Accept is the value of the accept option, which travels in the Accept
	// header and asks for the didDocument or contentStream alone; empty
	// asks for the complete result.
	Accept string `json:"accept,omitempty"`
	// Options are the options other than accept.
	Options map[string]any `json:"options,omitempty"`
}

// BindingProbe is a request without expectations of its own.
type BindingProbe struct {
	Note string `json:"note"`
	BindingRequest
}

// BindingScenario becomes one case.
type BindingScenario struct {
	Case string `json:"case"`
	Note string `json:"note"`
	BindingRequest
	// Compare first requests the complete result of the same call, for the
	// checks that compare the response with it.
	Compare bool `json:"compare,omitempty"`
	// UnsupportedIfStatus are status codes with which the subject declines
	// an optional part of the binding the scenario uses (the POST version);
	// the scenario's statements are then NOT_SUPPORTED.
	UnsupportedIfStatus []int         `json:"unsupportedIfStatus,omitempty"`
	Expect              []Expectation `json:"expect"`
}

// Statements returns the statements of all expectations without repeats.
func (sc BindingScenario) Statements() []string {
	lists := make([][]string, len(sc.Expect))
	for i, e := range sc.Expect {
		lists[i] = e.Statements
	}
	return Union(lists...)
}

func (b BindingRequest) method() string {
	if b.Method == "" {
		return http.MethodGet
	}
	return b.Method
}

// accept returns the Accept header: the accept option, or the media type
// of the complete result of the function.
func (b BindingRequest) accept() string {
	switch {
	case b.Accept != "":
		return b.Accept
	case b.Function == FnDereference:
		return checks.MediaTypeDIDURLDereferencing
	}
	return checks.MediaTypeDIDResolution
}

// full returns the request for the complete result of the same call.
func (b BindingRequest) full() BindingRequest {
	f := b
	f.Accept = ""
	return f
}

func (b BindingRequest) describe() string {
	opts := []byte("{}")
	if len(b.Options) > 0 {
		opts, _ = json.Marshal(b.Options)
	}
	return fmt.Sprintf("%s %s(%s) Accept: %s options %s", b.method(), b.Function, b.Input, b.accept(), opts)
}

// BindingOutcome is one exchange of a scenario.
type BindingOutcome struct {
	Endpoint string
	Request  BindingRequest
	Ex       core.HTTPExchange
	// Full is the exchange for the complete result of the same call, when
	// the scenario compares with it.
	Full *core.HTTPExchange
}

// ContentType returns the essence of the response's Content-Type.
func (o BindingOutcome) ContentType() string {
	return checks.MediaTypeEssence(o.Ex.Header.Get("Content-Type"))
}

// Result reads the body as the complete result of the request's function.
func (o BindingOutcome) Result() (checks.BindingResult, error) {
	return resultOf(o.Request.Function, o.Ex.Body)
}

func resultOf(fn string, body []byte) (checks.BindingResult, error) {
	if fn == FnDereference {
		return checks.ParseDereferencingResult(body)
	}
	return checks.ParseResolutionResult(body)
}

// Summary describes the response for an observation's observed value.
func (o BindingOutcome) Summary() string {
	return fmt.Sprintf("status %d, Content-Type %q, Location %q, body %q", o.Ex.Status, o.Ex.Header.Get("Content-Type"), o.Ex.Header.Get("Location"), clip(o.Ex.Body))
}

// Exchange builds the request with checks.BindingRequest and sends it.
func Exchange(ctx context.Context, s core.Subject, b BindingRequest) (core.HTTPExchange, error) {
	req, err := checks.BindingRequest(b.method(), b.Input, b.accept(), b.Options)
	if err != nil {
		return core.HTTPExchange{}, err
	}
	return s.(core.HTTPBinding).Exchange(ctx, req)
}

// BindingCheckFunc judges a binding outcome against an expectation's value.
type BindingCheckFunc func(o BindingOutcome, value json.RawMessage) (ok bool, expected, observed string)

// BindingChecks are the expectation checks binding scenarios can name.
var BindingChecks = map[string]BindingCheckFunc{
	"status":              bindingStatus,
	"contentType":         bindingContentType,
	"contentTypeOfResult": bindingContentTypeOfResult,
	"resolutionResult":    bindingResolutionResult,
	"dereferencingResult": bindingDereferencingResult,
	"resultContent":       bindingResultContent,
	"resultMetadataHas":   bindingResultMetadataHas,
	"bodyDocument":        bindingBodyDocument,
	"bodyMatchesResult":   bindingBodyMatchesResult,
	"location":            bindingLocation,
	"emptyBody":           bindingEmptyBody,
	"problemDetails":      bindingProblemDetails,
}

// BindingCases returns one case per binding scenario. Every scenario
// requests DIDs of the fixture method, so its case loads the registry
// first.
func BindingCases(profile string, reg *fixtures.Registry, f BindingFile) []core.Case {
	out := make([]core.Case, 0, len(f.Exchanges))
	for _, sc := range f.Exchanges {
		sts := sc.Statements()
		out = append(out, core.Case{
			ID:         profile + "/binding/" + sc.Case,
			Profile:    profile,
			Statements: sts,
			Needs:      []core.Capability{core.CapFixtureMethod, core.CapHTTPBinding},
			Run: RegistryCase(reg, sts, func(ctx context.Context, s core.Subject) []core.Observation {
				o, err := runBinding(ctx, s, sc.BindingRequest, sc.Compare)
				return JudgeBinding(sc, o, err)
			}),
		})
	}
	return out
}

func runBinding(ctx context.Context, s core.Subject, b BindingRequest, compare bool) (BindingOutcome, error) {
	o := BindingOutcome{Endpoint: s.(core.HTTPBinding).Endpoint(), Request: b}
	if compare {
		full, err := Exchange(ctx, s, b.full())
		if err != nil {
			return o, err
		}
		o.Full = &full
	}
	ex, err := Exchange(ctx, s, b)
	o.Ex = ex
	return o, err
}

// JudgeBinding turns an outcome into observations, one per statement of
// each expectation.
func JudgeBinding(sc BindingScenario, o BindingOutcome, err error) []core.Observation {
	var r Recorder
	input := sc.describe()
	if err != nil {
		r.All(sc.Statements(), core.Error, input, "no response: "+err.Error())
		return r.Observations()
	}
	if slices.Contains(sc.UnsupportedIfStatus, o.Ex.Status) {
		r.All(sc.Statements(), core.NotSupported, input, fmt.Sprintf("the subject declined an optional part of the binding with status %d", o.Ex.Status))
		return r.Observations()
	}
	for _, e := range sc.Expect {
		check, ok := BindingChecks[e.Check]
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

// BindingInvariant is a rule every response of the binding must satisfy.
type BindingInvariant struct {
	Statement string
	Partial   string
	Check     func(o BindingOutcome) (applies, ok bool, expected, observed string)
}

// BindingInvariantCase returns a case that sends every request of the
// scenarios (with their comparison requests) and probes and judges each
// invariant on each response it concerns. An invariant that no response
// concerns is NOT_APPLICABLE.
func BindingInvariantCase(id, profile string, reg *fixtures.Registry, invs []BindingInvariant, f BindingFile) core.Case {
	sts := make([]string, len(invs))
	for i, inv := range invs {
		sts[i] = inv.Statement
	}
	var reqs []BindingRequest
	for _, sc := range f.Exchanges {
		if sc.Compare {
			reqs = append(reqs, sc.full())
		}
		reqs = append(reqs, sc.BindingRequest)
	}
	for _, p := range f.Probes {
		reqs = append(reqs, p.BindingRequest)
	}
	return core.Case{
		ID:         id,
		Profile:    profile,
		Statements: sts,
		Needs:      []core.Capability{core.CapFixtureMethod, core.CapHTTPBinding},
		Run: RegistryCase(reg, sts, func(ctx context.Context, s core.Subject) []core.Observation {
			var r Recorder
			judged := make([]bool, len(invs))
			for _, b := range reqs {
				o, err := runBinding(ctx, s, b, false)
				if err != nil {
					continue
				}
				for i, inv := range invs {
					applies, ok, exp, obs := inv.Check(o)
					if !applies {
						continue
					}
					judged[i] = true
					r.Judge([]string{inv.Statement}, b.describe(), ok, exp, obs, inv.Partial)
				}
			}
			for i, inv := range invs {
				if !judged[i] {
					r.All([]string{inv.Statement}, core.NotApplicable, "", "no response of the scenarios concerned this statement")
				}
			}
			return r.Observations()
		}),
	}
}

// ValidateBinding checks a binding file: known functions, methods and
// checks, and statements on every expectation.
func ValidateBinding(f BindingFile) error {
	reqs := map[string]BindingRequest{}
	ids := map[string]bool{}
	for _, sc := range f.Exchanges {
		if sc.Case == "" || ids[sc.Case] {
			return fmt.Errorf("kit: binding scenario %q: empty or duplicate case", sc.Case)
		}
		ids[sc.Case] = true
		if len(sc.Expect) == 0 {
			return fmt.Errorf("kit: binding scenario %s: no expectation", sc.Case)
		}
		for _, e := range sc.Expect {
			if _, ok := BindingChecks[e.Check]; !ok || len(e.Statements) == 0 {
				return fmt.Errorf("kit: binding scenario %s: check %q unknown or without statements", sc.Case, e.Check)
			}
		}
		reqs[sc.Case] = sc.BindingRequest
	}
	for _, p := range f.Probes {
		reqs["probe "+p.Note] = p.BindingRequest
	}
	for name, b := range reqs {
		if b.Function != FnResolve && b.Function != FnDereference {
			return fmt.Errorf("kit: binding %s: function %q", name, b.Function)
		}
		if m := b.method(); m != http.MethodGet && m != http.MethodPost {
			return fmt.Errorf("kit: binding %s: method %q", name, m)
		}
	}
	return nil
}

func intsValue(v json.RawMessage) []int {
	var one int
	if json.Unmarshal(v, &one) == nil {
		return []int{one}
	}
	var many []int
	_ = json.Unmarshal(v, &many)
	return many
}

func bindingStatus(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := intsValue(v)
	return slices.Contains(want, o.Ex.Status), fmt.Sprintf("status %v", want), fmt.Sprintf("status %d", o.Ex.Status)
}

func bindingContentType(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	return slices.Contains(want, o.ContentType()), "Content-Type " + strings.Join(want, " or "), fmt.Sprintf("Content-Type %q", o.Ex.Header.Get("Content-Type"))
}

// fullResult reads the comparison exchange as the complete result.
func (o BindingOutcome) fullResult() (checks.BindingResult, string) {
	if o.Full == nil {
		return checks.BindingResult{}, "no complete result was requested"
	}
	r, err := resultOf(o.Request.Function, o.Full.Body)
	if err != nil {
		return checks.BindingResult{}, fmt.Sprintf("the complete result (status %d) cannot be read: %v", o.Full.Status, err)
	}
	return r, ""
}

func bindingContentTypeOfResult(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	r, why := o.fullResult()
	if why != "" {
		return false, "Content-Type equal to the contentType of the complete result", why
	}
	ct, ok := StringMember(r.Metadata, "contentType")
	if !ok {
		ct, ok = StringMember(r.ContentMetadata, "contentType")
	}
	if !ok {
		return false, "Content-Type equal to the contentType of the complete result", "the complete result has no contentType"
	}
	got := o.Ex.Header.Get("Content-Type")
	return got == ct, fmt.Sprintf("Content-Type %q (the contentType of the complete result)", ct), fmt.Sprintf("Content-Type %q", got)
}

func bindingResolutionResult(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	return resultForm(o, checks.MediaTypeDIDResolution, checks.ParseResolutionResult)
}

func bindingDereferencingResult(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	return resultForm(o, checks.MediaTypeDIDURLDereferencing, checks.ParseDereferencingResult)
}

func resultForm(o BindingOutcome, mediaType string, parse func([]byte) (checks.BindingResult, error)) (bool, string, string) {
	exp := "a body that is a " + mediaType + " result"
	if o.ContentType() != mediaType {
		return false, exp, fmt.Sprintf("Content-Type %q", o.Ex.Header.Get("Content-Type"))
	}
	if _, err := parse(o.Ex.Body); err != nil {
		return false, exp, err.Error() + ": " + clip(o.Ex.Body)
	}
	return true, "", ""
}

func bindingResultContent(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := absoluteID(baseDID(o.Request.Input), withoutContext(objectValue(v)))
	r, err := o.Result()
	if err != nil {
		return false, "a result whose content is " + checks.Compact(want.Value()), err.Error()
	}
	d, err := core.DocumentFromValue(r.Content)
	if err != nil {
		return false, checks.Compact(want.Value()), "content " + checks.Compact(r.Content)
	}
	got := absoluteID(baseDID(o.Request.Input), withoutContext(d))
	ok, at := checks.EqualJSON(got.Value(), want.Value())
	return ok, checks.Compact(want.Value()) + " (ignoring @context)", fmt.Sprintf("%s (first difference at %q)", checks.Compact(got.Value()), at)
}

func bindingResultMetadataHas(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := objectValue(v)
	r, err := o.Result()
	if err != nil {
		return false, "a result whose content metadata has " + checks.Compact(want.Value()), err.Error()
	}
	ok, name := checks.ContainsJSON(r.ContentMetadata, want)
	return ok, "content metadata with " + checks.Compact(want.Value()), fmt.Sprintf("member %q missing or different in %s", name, checks.Compact(r.ContentMetadata.Value()))
}

func bindingBodyDocument(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := withoutContext(objectValue(v))
	d, err := core.ParseDocumentJSON(o.Ex.Body)
	if err != nil {
		return false, "a body that is the JSON object " + checks.Compact(want.Value()), "body is not a JSON object: " + clip(o.Ex.Body)
	}
	got := withoutContext(d)
	ok, at := checks.EqualJSON(got.Value(), want.Value())
	return ok, checks.Compact(want.Value()) + " (ignoring @context)", fmt.Sprintf("%s (first difference at %q)", checks.Compact(got.Value()), at)
}

func bindingBodyMatchesResult(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	r, why := o.fullResult()
	exp := "a body equal to the content of the complete result"
	if why != "" {
		return false, exp, why
	}
	got, err := core.ParseJSON(o.Ex.Body)
	if err != nil {
		return false, exp, "body is not JSON: " + clip(o.Ex.Body)
	}
	ok, at := checks.EqualJSON(got, r.Content)
	return ok, exp + " " + checks.Compact(r.Content), fmt.Sprintf("%s (first difference at %q)", checks.Compact(got), at)
}

func bindingLocation(o BindingOutcome, v json.RawMessage) (bool, string, string) {
	want := stringsValue(v)
	got, has := o.Ex.Header["Location"]
	return has && slices.Equal(got, want), "Location " + strings.Join(want, " "), fmt.Sprintf("Location %q", got)
}

func bindingEmptyBody(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	return len(o.Ex.Body) == 0, "an empty body", fmt.Sprintf("body %q", clip(o.Ex.Body))
}

// bindingProblemDetails: the error is an RFC 9457 problem details object
// (application/problem+json) whose type is a URL.
func bindingProblemDetails(o BindingOutcome, _ json.RawMessage) (bool, string, string) {
	exp := "an application/problem+json body with a type URL (RFC 9457 §3, §4.1)"
	if o.ContentType() != checks.MediaTypeProblem {
		return false, exp, fmt.Sprintf("status %d, Content-Type %q", o.Ex.Status, o.Ex.Header.Get("Content-Type"))
	}
	v, err := core.ParseJSON(o.Ex.Body)
	if err != nil || v.Kind != core.KindObject {
		return false, exp, "body " + clip(o.Ex.Body)
	}
	t, _ := v.Get("type")
	return t.Kind == core.KindString && checks.IsAbsoluteURI(t.Str), exp, "body " + checks.Compact(v)
}

// EndpointIsHTTPS reports whether an endpoint URL has the https scheme.
func EndpointIsHTTPS(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https"
}
