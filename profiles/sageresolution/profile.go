package sageresolution

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"strings"
)

//go:embed cases.json
var caseBytes []byte

type expected struct {
	Check      string   `json:"check"`
	Value      any      `json:"value"`
	Statements []string `json:"statements"`
}
type scenario struct {
	Profile string `json:"profile"`
	Name    string `json:"name"`
	Record  int    `json:"record"`
	Request struct {
		Request
		Method       string `json:"http_method"`
		AcceptHeader string `json:"http_accept"`
	} `json:"request"`
	Expect []expected `json:"expect"`
}

// Profile preserves the pinned publications and uses SAGE-native cases only.
// It does not run the generic example method or reuse projection verdicts.
func Profile(name string) (core.Profile, error) {
	p, err := sageprojection.Profile(name)
	if err != nil {
		return p, err
	}
	p.Title = "SAGE record resolution, selected library and fixed-source actors and loopback HTTP observations; " + strings.TrimSuffix(p.Title, "; SAGE produced-document observations only")
	p.Cases = nil
	rows, err := sageprojection.Fixtures()
	if err != nil {
		return p, err
	}
	var cases []scenario
	if err = json.Unmarshal(caseBytes, &cases); err != nil {
		return p, err
	}
	for _, c := range cases {
		if c.Profile != name {
			continue
		}
		if c.Record < 0 || c.Record >= len(rows) {
			return p, fmt.Errorf("invalid record index")
		}
		q := c.Request.Request
		if q.Function == "http" || q.Function == "http-comparison" {
			req, e := checks.BindingRequest(c.Request.Method, q.Input, c.Request.AcceptHeader, q.Options)
			if e != nil {
				return p, e
			}
			q.HTTP = &req
		}
		ids := []string{}
		for _, ex := range c.Expect {
			for _, id := range ex.Statements {
				if !contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		record := rows[c.Record]
		p.Cases = append(p.Cases, core.Case{ID: name + "/sage-resolution/" + c.Name, Profile: name, Statements: ids, Run: func(ctx context.Context, s core.Subject) []core.Observation {
			target, ok := s.(Subject)
			if !ok {
				return unavailable(ids, core.NotSupported, "no SAGE resolution observation operation")
			}
			result, e := target.InspectResolution(ctx, record, q)
			if e != nil {
				return unavailable(ids, core.Error, e.Error())
			}
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			return judge(result, c.Expect, string(input))
		}})
	}
	appendNativeDocumentCases(&p, rows)
	if err := appendPublicJWKCases(&p, rows); err != nil {
		return p, err
	}
	appendNativeURLCases(&p, rows)
	appendNativeResultCases(&p, rows)
	appendMetadataCases(&p, rows)
	appendKeyFieldCases(&p, rows)
	appendRepresentationCases(&p, rows)
	appendPipelineCases(&p, rows)
	appendConsumptionBoundaryCases(&p, rows)
	appendTypedProductionCases(&p)
	appendTypedConsumptionCases(&p)
	appendRepresentationInputCases(&p)
	appendProducerContextCases(&p)
	if err := appendLibrarySyntaxCases(&p); err != nil {
		return p, err
	}
	appendLibraryCodecCases(&p)
	appendChoiceCodecCases(&p)
	appendChoiceClientCases(&p, rows)
	appendKeyConversionCases(&p)
	appendChoiceOptionalCases(&p)
	appendRepresentationOptionsCases(&p)
	appendResourceChoiceCases(&p)
	appendIntegerSourceCases(&p)
	appendFragmentSourceCases(&p)
	appendFragmentInitialCase(&p)
	appendFragmentSearchCases(&p)
	appendResolverProofCases(&p, rows)
	appendClientCases(&p, rows)
	appendRetrievalCases(&p, rows)
	appendLibraryDocumentCases(&p)
	appendLibraryContextCases(&p)
	appendContractCases(&p, rows)
	appendPolicyCases(&p)
	appendOptionalCases(&p)
	appendLibraryValueCases(&p)
	appendRemainingFieldCases(&p)
	appendRoutingCases(&p)
	appendRemainingNativeKeyCases(&p, rows)
	appendTrustCases(&p, rows)
	appendOperationCases(&p)
	appendRoutingBindingCases(&p)
	appendExpansionCases(&p)
	appendProxyCases(&p, rows)
	appendPreferenceCases(&p, rows)
	appendCIDHTTPCases(&p)
	appendMinimalCase(&p)
	if err := appendConsumerConformanceCases(&p); err != nil {
		return p, err
	}
	appendBranchCases(&p, rows)
	if err := appendWireCases(&p, rows); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func unavailable(ids []string, v core.Verdict, detail string) []core.Observation {
	out := make([]core.Observation, len(ids))
	for i, id := range ids {
		out[i] = core.Observation{Statement: id, Verdict: v, Detail: detail}
	}
	return out
}
