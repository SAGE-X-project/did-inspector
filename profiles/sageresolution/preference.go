package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

func judgePreference(fn string, values []Result, input string) []core.Observation {
	id := "res10-crd20261001#did-resolution-options.4"
	if fn == "dereference" {
		id = "res10-crd20261001#did-url-dereferencing-options.3"
	}
	obs := libraryUnavailable([]string{id}, core.Error, "Fresh actual SAGE native operations on the same public record, paired without accept and with the supported application/did preference. The absent preference follows the subject legacy default; this is not a DID 1.1 default-representation conformance claim. Only optional absence and the selected supported/available representation are examined; unsupported preferences, all media types, registry authority and operational deployment are not established.", input, values)
	if (fn != "resolve" && fn != "dereference") || len(values) != 2 {
		return obs
	}
	pass := true
	for i, v := range values {
		md, e := parse(v.Metadata)
		cm, e2 := parse(v.ContentMetadata)
		if e != nil || e2 != nil || v.Exchange != nil || v.Native != nil {
			return obs
		}
		if _, failed := md.Get("error"); failed {
			obs[0].Verdict = core.NotSupported
			return obs
		}
		ct, _ := md.Get("contentType")
		if ct.Kind != core.KindString {
			ct, _ = cm.Get("contentType")
		}
		pass = pass && v.HasContent && v.ContentKind == "document" && v.ReturnedID == policyDID && (i == 0 && (ct.Str == "application/did" || ct.Str == "application/did+json") || i == 1 && ct.Str == "application/did")
	}
	obs[0].Verdict = core.Fail
	if pass {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Absent optional accept accepted; selected supported application/did preference determines contentType"
	return obs
}
func appendPreferenceCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	r := records[0]
	for _, fn := range []string{"resolve", "dereference"} {
		id := "res10-crd20261001#did-resolution-options.4"
		if fn == "dereference" {
			id = "res10-crd20261001#did-url-dereferencing-options.3"
		}
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-preference-" + fn, Profile: p.Name, Statements: []string{id}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			qs := []Request{{Function: fn, Input: r.DID}, {Function: fn, Input: r.DID, Accept: "application/did"}}
			input, _ := json.Marshal(struct {
				Record   sageprojection.Record
				Requests []Request
			}{r, qs})
			s, ok := target.(Subject)
			if !ok {
				return libraryUnavailable([]string{id}, core.NotSupported, "no actual SAGE operation", string(input), nil)
			}
			values := []Result{}
			for _, q := range qs {
				v, e := s.InspectResolution(ctx, r, q)
				values = append(values, v)
				if e != nil {
					return libraryUnavailable([]string{id}, core.Error, e.Error(), string(input), values)
				}
			}
			return judgePreference(fn, values, string(input))
		}})
	}
}
