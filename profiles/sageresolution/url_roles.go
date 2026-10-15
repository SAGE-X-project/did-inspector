package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"reflect"
	"runtime"
)

var urlRoleIDs = []string{"res10-crd20261001#dereferencing-algorithm-resource.11", "cid10#retrieve-verification-method.3"}

//go:embed url_roles.json
var urlRoleBytes []byte

//go:embed url_roles_witness.json
var urlRoleWitness []byte

type urlHandlerFixture struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
	Request  Request         `json:"request"`
	Parts    URLParts        `json:"parts"`
	Adjusted URLParts        `json:"adjusted"`
	Calls    int             `json:"handler_calls"`
	Kind     string          `json:"expected_kind"`
	Content  json.RawMessage `json:"expected_content"`
	Error    string          `json:"diagnostic_error"`
}
type urlRetrievalFixture struct {
	Name    string                `json:"name"`
	Record  sageprojection.Record `json:"record"`
	Request RetrievalRequest      `json:"request"`
	Parts   URLParts              `json:"parts"`
	Calls   int                   `json:"calls"`
	Method  json.RawMessage       `json:"expected_method"`
}
type urlRoleFixture struct {
	Handlers  []urlHandlerFixture   `json:"handlers"`
	Retrieval []urlRetrievalFixture `json:"retrieval"`
}
type urlRoleEvidence struct {
	HandlerErrors   []string                 `json:"handler_errors,omitempty"`
	RetrievalErrors []string                 `json:"retrieval_errors,omitempty"`
	Source          IntegerSourceResult      `json:"source"`
	Audit           sourcearith.ServiceAudit `json:"audit"`
	Handler         []RoutingResult          `json:"handler"`
	Retrieval       []RetrievalResult        `json:"retrieval"`
	Compiler        string                   `json:"type_checker_compiler"`
	Architecture    string                   `json:"type_checker_architecture"`
	Error           string                   `json:"analysis_error,omitempty"`
}

func urlRoleFixtures() urlRoleFixture {
	var f urlRoleFixture
	_ = json.Unmarshal(urlRoleBytes, &f)
	return f
}
func urlRoleRequest() IntegerSourceRequest {
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"dereferencer", "relyingparty", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"}}
}
func urlRoleRouting(f urlHandlerFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request, ObserveResourceHandler: true}
}
func urlHandlerRuntime(values []RoutingResult) (bool, bool) {
	fs := urlRoleFixtures().Handlers
	if len(values) != len(fs) {
		return false, false
	}
	missing := false
	for i, v := range values {
		f := fs[i]
		if !reflect.DeepEqual(v.Request, urlRoleRouting(f)) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != IntegerSourceModule+"/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || v.Result.Native != nil || v.Result.Exchange != nil || len(v.ResourceHandler) != f.Calls || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:resources" || len(v.ResolveOptions) != 1 || len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:resources" || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || len(v.Consumption) != 1 {
			return false, false
		}
		if !optionJSONEqual(v.Options, `{"accept":"application/did"}`) || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"application/did","NoCache":false}`) || !optionJSONEqual(v.ResolvedMetadata, `{"contentType":"application/did"}`) || !optionJSONEqual(v.ResolvedDataModel, string(f.Document)) || !optionJSONEqual(v.DataModel, string(f.Document)) || !optionJSONEqual(v.ResolvedEntries, `{}`) || !optionJSONEqual(v.Entries, `{}`) {
			return false, false
		}
		opts := map[string]any{"accept": "application/did"}
		if f.Parts.HasQuery {
			opts["relativeRef"] = "next"
		}
		b, _ := json.Marshal(opts)
		if !optionJSONEqual(v.ResolveOptions[0], string(b)) {
			return false, false
		}
		read, e := parse(v.DriverResults[0])
		data, _ := read.Get("Data")
		ct, _ := read.Get("ContentType")
		body, e1 := base64.StdEncoding.DecodeString(data.Str)
		if e != nil || e1 != nil || ct.Str != "application/did" || !optionJSONEqual(body, string(f.Document)) {
			return false, false
		}
		c := v.Consumption[0]
		if c.Operation != pipelineConsumer || !bytes.Equal(c.Input, f.Document) || c.MediaType != "application/did" || c.Require != "unknown" || c.Expected != "unknown" || c.Strict || c.JSONLD || len(c.DroppedTerms) != 0 || c.Error != "" || c.CaptureError != "" || !optionJSONEqual(c.Model, string(f.Document)) || !optionJSONEqual(c.Entries, `{}`) {
			return false, false
		}
		for _, h := range v.ResourceHandler {
			if h.Operation != IntegerSourceModule+"/dereferencer.ResourceHandler" || h.Role != "literal passive resource handler; records actual values and returns unhandled" || h.CaptureError != "" || !optionJSONEqual(h.Options, `{"accept":"application/did"}`) || !optionJSONEqual(h.Model, string(v.ResolvedDataModel)) || !optionJSONEqual(h.Entries, `{}`) || !optionJSONEqual(h.Metadata, string(v.ResolvedMetadata)) {
				return false, false
			}
			if h.URL != f.Parts && h.URL != f.Adjusted {
				return false, false
			}
			if f.Parts.HasFragment && h.URL == f.Parts {
				missing = true
			}
		}
		md, e := parse(v.Result.Metadata)
		cm, e1 := parse(v.Result.ContentMetadata)
		raw, e2 := core.ParseJSON(v.Result.Raw)
		if e != nil || e1 != nil || e2 != nil || cm.Len() != 0 {
			return false, false
		}
		if f.Error != "" {
			if v.Result.HasContent || raw.Kind != core.KindNull || errorName(md) != f.Error {
				return false, false
			}
		} else {
			want, e := core.ParseJSON(f.Content)
			ct, _ := md.Get("contentType")
			_, failed := md.Get("error")
			if e != nil || !v.Result.HasContent || v.Result.ContentKind != f.Kind || failed || ct.Str != "application/ld+json" || !equalObserved(raw, want, "unknown") {
				return false, false
			}
		}
	}
	return true, missing
}
func urlRetrievalRuntime(values []RetrievalResult) bool {
	fs := urlRoleFixtures().Retrieval
	if len(values) != len(fs) {
		return false
	}
	for i, v := range values {
		f := fs[i]
		if v.Operation != IntegerSourceModule+"/relyingparty.RelyingParty.VerificationMethod" || v.Clock != 1800000000 || v.Reference != f.Request.Reference || v.Purpose != f.Request.Purpose || v.CaptureError != "" || v.ParsedURL == nil || *v.ParsedURL != f.Parts {
			return false
		}
		// Downstream refusal/output from these parser diagnostics is retained
		// verbatim but does not judge this independent extraction predicate.
		if string(f.Method) == "null" {
			continue
		}
		for _, call := range v.Calls {
			if call.Input != f.Parts.Primary || !optionJSONEqual(call.Options, `{}`) {
				return false
			}
		}
		if v.Error != "" || len(v.Problem) != 0 || v.ProblemSerializer != "" || !optionJSONEqual(v.Method, string(f.Method)) || len(v.Calls) != 1 {
			return false
		}
		call := v.Calls[0]
		if !call.Result.HasContent || call.Result.ReturnedID != f.Record.DID || call.Result.ContentKind != "document" {
			return false
		}
		model, e := core.ParseJSON(call.Result.Snapshot)
		id, _ := model.Get("id")
		methods, _ := model.Get("verificationMethod")
		rels, _ := model.Get(f.Request.Purpose)
		want, e1 := core.ParseJSON(f.Method)
		if e != nil || e1 != nil || id.Str != f.Record.DID || methods.Kind != core.KindArray || rels.Kind != core.KindArray {
			return false
		}
		found, linked := false, false
		for _, m := range methods.Array {
			if equalObserved(m, want, "unknown") {
				found = true
			}
		}
		for _, ref := range rels.Array {
			if ref.Kind == core.KindString && ref.Str == f.Request.Reference {
				linked = true
			}
		}
		if !found || !linked {
			return false
		}
	}
	return true
}
func urlRoleVerdict(a sourcearith.ServiceAudit, index int) core.Verdict {
	var w sourcearith.ServiceAudit
	if json.Unmarshal(urlRoleWitness, &w) != nil || !reflect.DeepEqual(a.Roots, w.Roots) || !reflect.DeepEqual(a.Frames, w.Frames) || !reflect.DeepEqual(a.CallPaths, w.CallPaths) || !reflect.DeepEqual(a.Roles, w.Roles) || len(a.Unknown) != 0 || len(a.Steps) != 2 || index < 0 || index >= 2 {
		return core.Error
	}
	if a.Steps[index].Kind != w.Steps[index].Kind {
		return core.Error
	}
	if !a.Steps[index].Correct {
		return core.Fail
	}
	return core.Pass
}
func finishURLRoles(ctx context.Context, e urlRoleEvidence, obs []core.Observation) []core.Observation {
	if ctx.Err() != nil {
		e.Error = ctx.Err().Error()
		for i := range obs {
			obs[i].Verdict = core.Error
		}
	}
	b, _ := json.Marshal(e)
	for i := range obs {
		obs[i].Observed = string(b)
	}
	return obs
}
func judgeURLRoles(ctx context.Context, e urlRoleEvidence, input string) []core.Observation {
	obs := libraryUnavailable(urlRoleIDs, core.Error, "Pinned typed URL operands and DID parser plus typed RP integration. Actual primary-resource handler URL is compared to an independent fragment-free literal; the passive observer always declines. Actual subject parser result is preserved and the same typed reference reaches RP/checkRef/SelectMethod/findMethod fragment access. Diagnostics from empty/percent/query references never become extraction failures. Reviewed helper context and Go semantics are premises; no full URL grammar, non-DID scheme, media-fragment (.fragment.3), output conformance, authority or physical trace claim. Modified source controls are parsed/type-checked only, never executed", input, e)
	v := e.Source
	q := urlRoleRequest()
	if e.Error != "" || !reflect.DeepEqual(v.Request, q) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Replaced || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return finishURLRoles(ctx, e, obs)
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil || sum != IntegerSourceSum {
		e.Error = "unbound URL source archive"
		return finishURLRoles(ctx, e, obs)
	}
	selected := sourcearith.SourceFiles(files, q.Packages)
	if len(selected) != 39 || len(v.Files) != 39 {
		e.Error = "incomplete URL source"
		return finishURLRoles(ctx, e, obs)
	}
	for n, b := range selected {
		if !bytes.Equal(v.Files[n], b) {
			e.Error = "URL cache differs from ZIP: " + n
			return finishURLRoles(ctx, e, obs)
		}
	}
	p := sourcearith.NewProgram(ctx, IntegerSourceModule, v.Files)
	for _, n := range []string{"dereferencer", "relyingparty"} {
		if _, err := p.Import(IntegerSourceModule + "/" + n); err != nil {
			e.Error = err.Error()
			return finishURLRoles(ctx, e, obs)
		}
	}
	e.Compiler, e.Architecture = runtime.Version(), runtime.GOARCH
	e.Audit = p.URLRolesAudit()
	valid, missing := urlHandlerRuntime(e.Handler)
	validRP := urlRetrievalRuntime(e.Retrieval)
	for i := range obs {
		obs[i].Verdict = urlRoleVerdict(e.Audit, i)
		if i == 0 && (!valid || len(e.HandlerErrors) != 0 || (obs[i].Verdict == core.Pass) == missing) {
			obs[i].Verdict = core.Error
		}
		if i == 1 && (!validRP || len(e.RetrievalErrors) != 0) {
			obs[i].Verdict = core.Error
		}
		obs[i].Expected = "Fragment-free actual primary-resource handler input; independent literal DID fragment retained by parser and used in the same typed relying-party reference"
	}
	return finishURLRoles(ctx, e, obs)
}
func appendURLRolesCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/url-source-roles", Profile: p.Name, Statements: urlRoleIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		s, ok := target.(IntegerSourceSubject)
		r, ok1 := target.(RoutingSubject)
		rp, ok2 := target.(RetrievalSubject)
		q := urlRoleRequest()
		b, _ := json.Marshal(q)
		input := string(b)
		if !ok || !ok1 || !ok2 {
			return libraryUnavailable(urlRoleIDs, core.NotSupported, "no selected source/routing/retrieval operations", input, nil)
		}
		e := urlRoleEvidence{Handler: []RoutingResult{}, Retrieval: []RetrievalResult{}}
		var err error
		e.Source, err = s.InspectIntegerSource(ctx, q)
		if err != nil {
			e.Error = err.Error()
			return judgeURLRoles(ctx, e, input)
		}
		f := urlRoleFixtures()
		for _, v := range f.Handlers {
			value, err := r.InspectRouting(ctx, urlRoleRouting(v))
			e.Handler = append(e.Handler, value)
			if err != nil {
				e.HandlerErrors = append(e.HandlerErrors, err.Error())
			}
		}
		for _, v := range f.Retrieval {
			value, err := rp.InspectRetrieval(ctx, v.Record, v.Request)
			e.Retrieval = append(e.Retrieval, value)
			if err != nil {
				e.RetrievalErrors = append(e.RetrievalErrors, err.Error())
			}
		}
		return judgeURLRoles(ctx, e, input)
	}})
}
