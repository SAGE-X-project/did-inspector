package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

type operationFixture struct {
	Name     string
	ID       string
	Requests []LibraryOperationRequest
	Values   map[string]string
	Time     string
}

func operationFixtures() []operationFixture {
	return []operationFixture{
		{Name: "parameters-ascii", ID: "res10-crd20261001#did-parameters.1", Requests: []LibraryOperationRequest{{Kind: "parameters", Input: "did:example:123?service=one&relativeRef=..%2Fsend&extension=%E2%9C%93"}, {Kind: "parameters", Input: "did:example:123?extension=✓"}}, Values: map[string]string{"service": "one", "relativeRef": "../send", "extension": "✓"}},
		{Name: "parameters-time", ID: "res10-crd20261001#did-parameters.3", Requests: []LibraryOperationRequest{{Kind: "parameters", Input: "did:example:123?versionTime=2030-01-02T03%3A04%3A05Z"}, {Kind: "parameters", Input: "did:example:123?versionTime=2030-01-02T03%3A04%3A05.1Z"}, {Kind: "parameters", Input: "did:example:123?versionTime=2030-01-02T03%3A04%3A05%2B00%3A00"}, {Kind: "parameters", Input: "did:example:123?versionTime=2030-02-30T03%3A04%3A05Z"}}, Values: map[string]string{"versionTime": "2030-01-02T03:04:05Z"}, Time: "2030-01-02T03:04:05Z"},
		{Name: "cache-refusal", ID: "res10-crd20261001#caching.2", Requests: []LibraryOperationRequest{{Kind: "cache", Input: "did:example:123", Refuse: false}, {Kind: "cache", Input: "did:example:123", Refuse: true}}},
	}
}
func judgeOperation(f operationFixture, values []LibraryOperationResult, input string) []core.Observation {
	out := libraryUnavailable([]string{f.ID}, core.Error, "Actual pinned selected library parser/cache, with independent literal positive and refusal controls. URI wire bytes are distinguished from percent-decoded Unicode scalar values. Cache results come from an explicitly named literal inner resolver, not a verifiable registry. No historical timestamp, operational authority or deployed cache policy is established.", input, values)
	known := false
	for _, candidate := range operationFixtures() {
		if reflect.DeepEqual(f, candidate) {
			known = true
		}
	}
	if !known || len(values) != len(f.Requests) {
		return out
	}
	for i, v := range values {
		want := "github.com/sage-x-project/did-go/did.DIDURL.Parameters"
		if f.Requests[i].Kind == "cache" {
			want = "github.com/sage-x-project/did-go/resolution/cache.Resolver.Resolve"
		}
		parseRefusal := f.Name == "parameters-ascii" && i == 1 && v.Operation == "" && v.Error != "" && v.Wire == ""
		if v.Request != f.Requests[i] || (!parseRefusal && v.Operation != want) || (f.Requests[i].Kind == "parameters" && v.ParseOperation != "github.com/sage-x-project/did-go/did.ParseURL") {
			return out
		}
	}
	pass := true
	unreviewedDetail := false
	if f.Requests[0].Kind == "parameters" {
		good := values[0]
		pass = good.Error == "" && good.Wire == f.Requests[0].Input && reflect.DeepEqual(good.Values, f.Values) && good.VersionTime == f.Time
		for _, v := range values[1:] {
			pass = pass && v.Error != "" && len(v.Values) == 0 && v.VersionTime == ""
		}
	} else {
		for i, v := range values {
			if v.Error != "" || len(v.Results) != 3 {
				return out
			}
			wantCalls := 2
			if i == 1 {
				wantCalls = 1
			}
			pass = pass && v.Calls == wantCalls
			for j, r := range v.Results {
				md, e := parse(r.Metadata)
				if e != nil {
					return out
				}
				if i == 1 && j == 1 {
					er, _ := md.Get("error")
					typ, _ := er.Get("type")
					detail, _ := er.Get("detail")
					if detail.Kind == core.KindString && detail.Str != "" && detail.Str != "bypassing the cache (noCache) is not permitted by this resolver; resolve again without noCache" && detail.Str != "noCache not permitted; retry without noCache" {
						unreviewedDetail = true
					}
					pass = pass && nativeErrorDescriptor(md) && typ.Str == "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED" && detail.Kind == core.KindString && detail.Str != "" && len(r.Raw) == 0
				} else {
					_, err := md.Get("error")
					pass = pass && !err && string(r.Raw) == `{"id":"did:example:123"}`
				}
			}
		}
	}
	out[0].Verdict = core.Fail
	if pass {
		out[0].Verdict = core.Pass
		if unreviewedDetail {
			out[0].Verdict = core.NotSupported
			out[0].Detail += " Unreviewed natural-language explanation requires an independent semantic review; wording differences alone are not a normative failure."
		}
	}
	out[0].Expected = "Independent fixed literal output and actual refusal controls, with exact API/input attribution"
	return out
}
func appendOperationCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range operationFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-operation-" + f.Name, Profile: p.Name, Statements: []string{f.ID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f.Requests)
			s, ok := target.(LibraryOperationSubject)
			if !ok {
				return libraryUnavailable([]string{f.ID}, core.NotSupported, "no selected library operation", string(input), nil)
			}
			values := []LibraryOperationResult{}
			for _, q := range f.Requests {
				v, e := s.InspectLibraryOperation(ctx, q)
				values = append(values, v)
				if e != nil {
					return libraryUnavailable([]string{f.ID}, core.Error, e.Error(), string(input), values)
				}
			}
			return judgeOperation(f, values, string(input))
		}})
	}
}
