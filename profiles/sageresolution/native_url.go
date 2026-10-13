package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	whatwg "github.com/nlnwa/whatwg-url/url"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"golang.org/x/net/idna"
)

const urlParserEvidence = "github.com/nlnwa/whatwg-url v0.6.2 (605b909fe66d0472311892f4feed6b4de3e2bdb8); WHATWG URL reviewed 2026-10-13 at fde3f74f063341a28d437216f75735b8b40128f5; golang.org/x/net/idna v0.61.0 strict ToASCII (STD3, labels, hyphens, DNS length); fail on validation errors; no base"

var nativeURLStatements = []string{"cid10#subjects.1", "cid10#controllers.3", "cid10#verification-methods.5", "cid10#verification-methods.7", "cid10#services.6", "cid10#services.13", "did11-cr20260305#core-properties.1"}

// The selected scope is ASCII opaque did: URLs and HTTPS DNS URLs. Relative
// references, other schemes, IDNA and IP host semantics are not established.
// Classification never replaces the original input with a normalized URL.
func nativeURLValue(v core.Value) core.Verdict {
	if v.Kind != core.KindString || v.Str == "" {
		return core.Fail
	}
	for _, ch := range v.Str {
		if ch > 127 {
			return core.NotSupported
		}
	}
	// Trimming identifies the supported scheme only. Parse always receives the
	// unmodified string and rejects otherwise recoverable validation errors.
	candidate := strings.ToLower(strings.TrimSpace(v.Str))
	scheme, rest, found := strings.Cut(candidate, ":")
	if !found || (scheme != "did" && scheme != "https") {
		return core.NotSupported
	}
	if scheme == "did" && strings.HasPrefix(rest, "/") {
		return core.NotSupported
	}
	if scheme == "https" {
		authority := strings.TrimPrefix(rest, "//")
		if i := strings.IndexAny(authority, "/\\?#"); i >= 0 {
			authority = authority[:i]
		}
		if strings.ContainsAny(authority, "%[") || strings.Contains(authority, "xn--") {
			return core.NotSupported
		}
		host := authority
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		host, _, _ = strings.Cut(host, ":")
		last := host[strings.LastIndex(host, ".")+1:]
		if strings.HasPrefix(last, "0x") || (last != "" && last[0] >= '0' && last[0] <= '9') {
			return core.NotSupported
		}
		// v0.6.2 predates strict-domain error reporting in the current standard.
		// Independently enforce the strict ToASCII pass, even for ASCII domains.
		strictDNS := idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.CheckHyphens(true), idna.VerifyDNSLength(true))
		if _, err := strictDNS.ToASCII(host); err != nil {
			return core.Fail
		}
	}
	parser := whatwg.NewParser(whatwg.WithReportValidationErrors(), whatwg.WithFailOnValidationError())
	u, err := parser.Parse(v.Str)
	if err != nil || u == nil {
		return core.Fail
	}
	if len(u.ValidationErrors()) != 0 {
		return core.Fail
	}
	if scheme == "https" {
		// Even canonical IPv4 hosts stay outside the reviewed DNS host scope.
		host := u.Hostname()
		numeric := host != ""
		for _, ch := range host {
			if (ch < '0' || ch > '9') && ch != '.' {
				numeric = false
			}
		}
		if numeric {
			return core.NotSupported
		}
	}
	return core.Pass
}
func aggregateURLs(values []core.Value) core.Verdict {
	if len(values) == 0 {
		return core.NotApplicable
	}
	verdicts := make([]core.Verdict, 0, len(values))
	for _, v := range values {
		verdicts = append(verdicts, nativeURLValue(v))
	}
	return core.Aggregate(verdicts)
}
func nativeURLMethods(d core.DocumentJSON) ([]core.Value, error) {
	var methods []core.Value
	if v, present := d.Get("verificationMethod"); present {
		if !nativeMaps(v) {
			return nil, fmt.Errorf("invalid native verification method set")
		}
		methods = append(methods, v.Array...)
	}
	for _, key := range []string{"authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"} {
		v, present := d.Get(key)
		if !present {
			continue
		}
		if v.Kind != core.KindArray {
			return nil, fmt.Errorf("invalid native relationship set")
		}
		for _, item := range v.Array {
			switch item.Kind {
			case core.KindObject:
				methods = append(methods, item)
			case core.KindString: // References are not embedded method definitions.
			default:
				return nil, fmt.Errorf("invalid native relationship entry")
			}
		}
	}
	return methods, nil
}
func nativeMethodURLs(d core.DocumentJSON, key string) core.Verdict {
	methods, err := nativeURLMethods(d)
	if err != nil {
		return core.Error
	}
	values := make([]core.Value, 0, len(methods))
	for _, m := range methods {
		v, _ := m.Get(key)
		values = append(values, v)
	}
	return aggregateURLs(values)
}
func nativeControllerURLs(d core.DocumentJSON) core.Verdict {
	v, present := d.Get("controller")
	if !present {
		return core.NotApplicable
	}
	if v.Kind == core.KindString {
		return nativeURLValue(v)
	}
	if v.Kind != core.KindArray || !nativeUnique(v.Array) {
		return core.Fail
	}
	return aggregateURLs(v.Array)
}
func nativeServiceURLs(d core.DocumentJSON, endpoint bool) core.Verdict {
	services, present := d.Get("service")
	if !present {
		return core.NotApplicable
	}
	if !nativeMaps(services) {
		return core.Error
	}
	var values []core.Value
	for _, service := range services.Array {
		key := "id"
		if endpoint {
			key = "serviceEndpoint"
		}
		v, present := service.Get(key)
		if !present {
			continue
		}
		if !endpoint {
			values = append(values, v)
			continue
		}
		switch v.Kind {
		case core.KindString:
			values = append(values, v)
		case core.KindObject: // Map semantics do not make every nested string a URL.
		case core.KindArray:
			for _, item := range v.Array {
				switch item.Kind {
				case core.KindString:
					values = append(values, item)
				case core.KindObject:
				default:
					return core.Error
				}
			}
		default:
			return core.Error
		}
	}
	return aggregateURLs(values)
}
func judgeNativeURLs(o Result, input string) []core.Observation {
	unavailableWithInput := func(detail string) []core.Observation {
		obs := unavailable(nativeURLStatements, core.Error, detail)
		for i := range obs {
			obs[i].Input = input
		}
		return obs
	}
	md, err := parse(o.Metadata)
	if err != nil {
		return unavailableWithInput(err.Error())
	}
	mt, _ := md.Get("contentType")
	if !o.HasContent || o.ContentKind != "document" || mt.Kind != core.KindString || checks.MediaTypeEssence(mt.Str) != "application/did" {
		return unavailableWithInput("URL inspection requires actual DID 1.1 document")
	}
	if _, failed := md.Get("error"); failed {
		return unavailableWithInput("native resolution failed")
	}
	doc, err := parse(o.Snapshot)
	if err != nil {
		return unavailableWithInput(err.Error())
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return unavailableWithInput(err.Error())
	}
	id, _ := doc.Get("id")
	endpoints := nativeServiceURLs(doc, true)
	verdicts := []core.Verdict{nativeURLValue(id), nativeControllerURLs(doc), nativeMethodURLs(doc, "id"), nativeMethodURLs(doc, "controller"), nativeServiceURLs(doc, false), endpoints, endpoints}
	obs := make([]core.Observation, len(nativeURLStatements))
	for i, statement := range nativeURLStatements {
		obs[i] = core.Observation{Statement: statement, Verdict: verdicts[i], Input: input, Expected: "Applicable selected URL strings parse without failure or validation errors", Observed: string(raw), Detail: urlParserEvidence + ". Actual accessor snapshot only; selected ASCII opaque DID and HTTPS DNS URL syntax. Unsupported schemes, relative/base resolution, IP/IDNA hosts, authority, endpoint reachability and full URL Standard conformance are unestablished. Optional absent fields or no applicable strings are NOT_APPLICABLE; map endpoint strings are not guessed to be URLs. No source value is repaired and no subject validator or verdict is reused."}
	}
	return obs
}
func appendNativeURLCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-url-record-%d", p.Name, i), Profile: p.Name, Statements: append([]string{}, nativeURLStatements...), Run: func(ctx context.Context, s core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			result, ok := s.(Subject)
			if !ok {
				obs := unavailable(nativeURLStatements, core.NotSupported, "no native resolution operation")
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			actual, err := result.InspectResolution(ctx, record, q)
			if err != nil {
				obs := unavailable(nativeURLStatements, core.Error, err.Error())
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			return judgeNativeURLs(actual, string(input))
		}})
	}
}
