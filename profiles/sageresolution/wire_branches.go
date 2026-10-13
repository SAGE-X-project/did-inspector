package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

type wireScenario struct {
	kind, method string
	request      Request
	record       int
}

func wireStatements(s wireScenario) []string {
	var numbers []string
	switch s.kind {
	case "resolve-envelope":
		numbers = []string{"25", "26"}
	case "resolve-direct":
		numbers = []string{"25", "28", "30"}
	case "dereference-envelope":
		numbers = []string{"32", "33"}
	case "dereference-direct":
		numbers = []string{"32", "39", "41", "42"}
	case "deactivated":
		numbers = []string{"23"}
	}
	if s.method == "GET" {
		numbers = append(numbers, "1")
	}
	out := make([]string, 0, len(numbers))
	for _, n := range numbers {
		out = append(out, resolutionPrefix+"bindings-https."+n)
	}
	return out
}
func judgeWire(result Result, s wireScenario, input string) []core.Observation {
	ids := wireStatements(s)
	missing := func(detail string) []core.Observation {
		out := unavailable(ids, core.Error, detail)
		for i := range out {
			out[i].Input = input
		}
		return out
	}
	if result.Exchange == nil || result.Native == nil || result.Native.Result == nil {
		return missing("missing actual wire/native counterpart")
	}
	if result.Native.Request.Function != s.request.NativeFunction || result.Native.Request.Input != s.request.Input || result.Native.Request.Accept != s.request.Accept {
		return missing("native input does not match the independently selected wire scenario")
	}
	if s.request.HTTP == nil || result.Exchange.Method != s.method || !result.Exchange.TLS || result.Exchange.RequestHeader.Get("Accept") != s.request.HTTP.Header.Get("Accept") || !bytes.Equal(result.Exchange.RequestBody, s.request.HTTP.Body) {
		return missing("wire request or TLS channel does not match the selected scenario")
	}
	native := result.Native.Result
	ex := result.Exchange
	md, err := parse(native.Metadata)
	if err != nil {
		return missing(err.Error())
	}
	cm, err := parse(native.ContentMetadata)
	if err != nil {
		return missing(err.Error())
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return missing(err.Error())
	}
	var valid bool
	header := ex.Header.Get("Content-Type")
	contentType, _ := md.Get("contentType")
	_, hasError := md.Get("error")
	success := native.HasContent && !hasError
	switch s.kind {
	case "resolve-envelope", "dereference-envelope":
		same, err := checkHTTPNative(result, expected{Value: s.request.NativeFunction})
		valid = err == nil && same && success && ex.Status == 200
	case "deactivated":
		marker, _ := cm.Get("deactivated")
		same, err := checkHTTPNative(result, expected{Value: "resolve"})
		valid = err == nil && same && marker.Kind == core.KindBool && marker.Bool && !native.HasContent && !hasError && ex.Status == 410
	default:
		body, err := core.ParseJSON(ex.Body)
		expectedBody, e := core.ParseJSON(native.Raw)
		valid = success && ex.Status == 200 && contentType.Kind == core.KindString && header == contentType.Str && err == nil && e == nil && len(checks.DuplicateMembers(body)) == 0 && len(checks.DuplicateMembers(expectedBody)) == 0 && equalObserved(body, expectedBody, "unknown")
	}
	out := make([]core.Observation, 0, len(ids))
	for _, id := range ids {
		pass := valid
		if id == resolutionPrefix+"bindings-https.30" || id == resolutionPrefix+"bindings-https.41" {
			pass = success && contentType.Kind == core.KindString && contentType.Str != "" && header == contentType.Str
		}
		if id == resolutionPrefix+"bindings-https.42" {
			body, err := core.ParseJSON(ex.Body)
			expectedBody, e := core.ParseJSON(native.Raw)
			pass = success && contentType.Kind == core.KindString && contentType.Str != "" && header == contentType.Str && err == nil && e == nil && len(checks.DuplicateMembers(body)) == 0 && len(checks.DuplicateMembers(expectedBody)) == 0 && equalObserved(body, expectedBody, "unknown")
		}
		verdict := core.Pass
		if !pass {
			verdict = core.Fail
		}
		out = append(out, core.Observation{Statement: id, Verdict: verdict, Input: input, Expected: "Selected HTTPS response branch matches its separate native result", Observed: string(raw), Detail: "Fresh inspector-owned loopback TLS GET/POST and a separate actual native call on the same fixed public record. Response status, exact media-type header and complete selected JSON body are checked. Parent clauses establish this branch only, not all options/representations, client request construction, production ingress, VDR authority or general conformance. No service endpoint, external target or private key is used."})
	}
	return out
}
func appendWireCases(p *core.Profile, rows []sageprojection.Record) error {
	if p.Name != "did-1.1" {
		return nil
	}
	for _, method := range []string{"GET", "POST"} {
		for _, kind := range []string{"resolve-envelope", "resolve-direct", "dereference-envelope", "dereference-direct", "deactivated"} {
			function, accept, nativeAccept, input, record := "resolve", checks.MediaTypeDIDResolution, "", rows[0].DID, 0
			if strings.HasPrefix(kind, "dereference") {
				function = "dereference"
				input += "#sign"
				accept = checks.MediaTypeDIDURLDereferencing
			}
			if strings.HasSuffix(kind, "direct") {
				accept = "application/did"
				nativeAccept = accept
			}
			if kind == "deactivated" {
				record = 4
				input = rows[record].DID
			}
			http, err := checks.BindingRequest(method, input, accept, nil)
			if err != nil {
				return err
			}
			s := wireScenario{kind: kind, method: method, record: record, request: Request{Function: "http-comparison", NativeFunction: function, Input: input, Accept: nativeAccept, HTTP: &http}}
			ids := wireStatements(s)
			p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/wire-branch-" + strings.ToLower(method) + "-" + kind, Profile: p.Name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
				input, _ := json.Marshal(struct {
					Record  sageprojection.Record `json:"record"`
					Request Request               `json:"request"`
				}{rows[s.record], s.request})
				missing := func(v core.Verdict, detail string) []core.Observation {
					out := unavailable(ids, v, detail)
					for i := range out {
						out[i].Input = string(input)
					}
					return out
				}
				subject, ok := target.(Subject)
				if !ok {
					return missing(core.NotSupported, "no owned TLS/native observation")
				}
				actual, err := subject.InspectResolution(ctx, rows[s.record], s.request)
				if err != nil {
					return missing(core.Error, err.Error())
				}
				return judgeWire(actual, s, string(input))
			}})
		}
	}
	return nil
}
