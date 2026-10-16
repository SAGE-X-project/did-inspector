package sage

import (
	"context"
	"encoding/json"
	"errors"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/document"
	"net/http"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
)

func TestNativeResolutionProfilesWithStaticSourceFixture(t *testing.T) {
	s, err := identify(pinned)
	if err != nil {
		t.Fatal(err)
	}
	// Go test binaries do not reliably retain dependency build metadata.
	// Static-source unit coverage uses an explicit data fixture; the native CLI
	// test independently checks real build metadata and actual cache/ZIP files.
	fixture, _ := sourceTest(t)
	s.sourceObserver = fixture.sourceObserver
	target := s.ResolutionIdentity()
	if target.Describe().Name == s.Describe().Name {
		t.Fatal("mixed scopes")
	}
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p, e := sageresolution.Profile(name)
		if e != nil {
			t.Fatal(e)
		}
		res, e := (core.Runner{}).Run(t.Context(), p, target)
		if e != nil {
			t.Fatal(e)
		}
		in, e := report.InputFor(p, res, "unit-native")
		if e != nil {
			t.Fatal(e)
		}
		r := report.Build(in)
		t.Log(name, r.Totals)
		for _, c := range res.Cases {
			for _, o := range c.Observations {
				allowed := o.Verdict == core.Pass
				if o.Verdict == core.NotApplicable && strings.Contains(c.Case, "/native-document-record-") {
					allowed = true
				}
				if o.Verdict == core.NotApplicable && strings.Contains(c.Case, "/native-url-record-") && o.Statement == "cid10#controllers.3" {
					allowed = true
				}
				if o.Verdict == core.NotApplicable && strings.Contains(c.Case, "/native-result-active-record-") && (o.Statement == "res10-crd20261001#resolving.5" || o.Statement == "res10-crd20261001#did-document-metadata.7") {
					allowed = true
				}
				if o.Verdict == core.Fail && strings.Contains(c.Case, "/native-key-fields-") && o.Statement == "cid10#JsonWebKey.7" {
					allowed = true
				}
				if o.Verdict == core.Fail && strings.Contains(c.Case, "/library-context-producer-") && o.Statement == "did11-cr20260305#json-ld-processors.6" {
					allowed = true
				}
				if o.Verdict == core.Fail && strings.Contains(c.Case, "/key-policy-format-") && (o.Statement == "cid10#verification-methods.9" || o.Statement == "cid10#verification-methods.11" || o.Statement == "cid10#conformance.2" || o.Statement == "did11-cr20260305#production-and-consumption.18") {
					allowed = true
				}
				if o.Verdict == core.Fail && strings.HasSuffix(c.Case, "/remaining-routing-forward-uri-options") && o.Statement == "res10-crd20261001#dereferencing-algorithm-resource.5" {
					allowed = true
				}
				if strings.HasSuffix(c.Case, "/remaining-native-keys") && ((o.Verdict == core.Fail && o.Statement == "cid10#JsonWebKey.5") || (o.Verdict == core.NotApplicable && (o.Statement == "cid10#JsonWebKey.6" || o.Statement == "cid10#JsonWebKey.9"))) {
					allowed = true
				}
				if o.Verdict == core.Fail && strings.HasSuffix(c.Case, "/remaining-proxy-metadata") && o.Statement == "res10-crd20261001#resolver-architectures-proxied.2" {
					allowed = true
				}
				if o.Verdict == core.Fail && o.Statement == "cid10#fragment-resolution.4" {
					for _, holder := range []string{"method-extra", "embedded-extra", "service-extra", "endpoint-map"} {
						if c.Case == "did-1.1/sage-resolution/fragment-search-"+holder {
							allowed = true
						}
					}
				}
				if o.Verdict == core.Fail && c.Case == "did-1.1/sage-resolution/expansion-source-roles" && o.Statement == "res10-crd20261001#resolving-algorithm.28" {
					allowed = true
				}
				if o.Verdict == core.Fail && c.Case == "did-1.1/sage-resolution/url-source-roles" && o.Statement == "res10-crd20261001#dereferencing-algorithm-resource.11" {
					allowed = true
				}
				if o.Verdict == core.Fail && c.Case == "did-1.1/sage-resolution/item-expansion-conditions" && o.Statement == "res10-crd20261001#resolving-algorithm.29" {
					allowed = true
				}
				if o.Verdict == core.NotSupported && c.Case == "did-1.1/sage-resolution/extension-codecs" && (o.Statement == "cid10#multibase-0.1" || o.Statement == "cid10#multihash.1") {
					allowed = true
				}
				if !allowed {
					t.Errorf("%s %s: %s %s", c.Case, o.Statement, o.Verdict, o.Observed)
				}
			}
		}
		if !expectedResolutionGate(r) {
			t.Fatal(r.GateFailures())
		}
	}
}
func TestResolutionTranslationFailures(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	q := sageresolution.Request{Function: "resolve", Input: rows[0].DID}
	bad := rows[0]
	bad.DID = "bad"
	if _, e := s.InspectResolution(t.Context(), bad, q); e == nil {
		t.Fatal("bad fixture DID")
	}
	bad = rows[0]
	bad.Keys = append([]sageprojection.Key(nil), bad.Keys...)
	bad.Keys[0].MaterialHex = "zz"
	if _, e := s.InspectResolution(t.Context(), bad, q); e == nil {
		t.Fatal("bad fixture bytes")
	}
	for _, request := range []sageresolution.Request{{Function: "bad"}, {Function: "http"}, {Function: "resolve10", Input: "bad"}, {Function: "dereference", Input: "bad"}} {
		if _, e := s.InspectResolution(t.Context(), rows[0], request); e == nil {
			t.Fatal(request)
		}
	}
	req := core.HTTPRequest{Method: http.MethodGet, Target: "did:sage:web:registry.example:agent-1", Header: http.Header{}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := s.InspectResolution(ctx, rows[0], sageresolution.Request{Function: "http", HTTP: &req}); e == nil {
		t.Fatal("canceled exchange")
	}
	if _, e := nativeResult(sageresolution.Result{}, func() {}, document.Metadata{}); e == nil {
		t.Fatal("native metadata encoding")
	}
	if _, e := nativeResult(sageresolution.Result{}, map[string]any{}, document.Metadata{Extra: map[string]any{"bad": func() {}}}); e == nil {
		t.Fatal("content metadata encoding")
	}
	if _, e := dereferenceResult(sageresolution.Result{}, nil, func() {}, document.Metadata{}); e == nil {
		t.Fatal("content encoding")
	}
	// Native metadata remains unchanged: the known SAGE-only missing member is
	// not repaired by adapter translation.
	out, e := s.InspectResolution(t.Context(), rows[0], q)
	if e != nil {
		t.Fatal(e)
	}
	var md map[string]any
	if e = json.Unmarshal(out.ContentMetadata, &md); e != nil {
		t.Fatal(e)
	}
	if md["versionId"] != "7" {
		t.Fatal("fixture version not preserved")
	}
	if _, ok := md["deactivated"]; ok {
		t.Fatal("adapter inserted active metadata")
	}
}

func TestNativeRecordOutcomesRemainUnrepaired(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	for _, fn := range []string{"resolve", "resolve10", "representation10"} {
		out, e := s.InspectResolution(t.Context(), rows[4], sageresolution.Request{Function: fn, Input: rows[4].DID})
		if e != nil || out.HasContent {
			t.Fatal("deactivation output", fn, e)
		}
		var md map[string]any
		if e = json.Unmarshal(out.ContentMetadata, &md); e != nil || md["deactivated"] != true {
			t.Fatal("deactivation metadata", fn, e)
		}
	}
	out, e := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "resolve", Input: rows[0].DID, Accept: "text/html"})
	if e != nil || out.HasContent || out.SageCode != "" {
		t.Fatal("known unsupported accept boundary repaired", e)
	}
	out, e = s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "resolve10", Input: rows[0].DID})
	if e != nil || !json.Valid(out.Snapshot) || len(out.Raw) != 0 {
		t.Fatal("native snapshot scope", e, out)
	}
}

func TestActualComparisonsArchiveBothInputsAndAllFields(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	for _, fn := range []string{"resolve", "resolve10", "dereference", "dereference10"} {
		out, err := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: fn, Input: rows[0].DID})
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = json.Unmarshal(out.Snapshot, &doc); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"id", "verificationMethod", "authentication", "assertionMethod", "keyAgreement", "service"} {
			if _, present := doc[field]; !present {
				t.Fatal("lost native field", fn, field)
			}
		}
	}
	// Invalid comparison configuration is rejected; no native result is invented.
	req := core.HTTPRequest{Method: "GET", Target: rows[0].DID, Header: http.Header{"Accept": {"application/did-resolution"}}}
	if _, err := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "http-comparison", Input: rows[0].DID, HTTP: &req}); err == nil {
		t.Fatal("implicit comparison operation")
	}
	if _, err := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "http-comparison", NativeFunction: "dereference", Input: "invalid", HTTP: &req}); err == nil {
		t.Fatal("invalid native input")
	}
}

func TestUnexpectedSourceIsAnOrdinaryErrorAndNotAbsence(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	rec, err := resolutionRecord(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = (resolutionSource{record: rec, failure: "fixture.unexpected"}).Observe(t.Context(), rec.DID)
	var sageError *didsage.Error
	if err == nil || errors.As(err, &sageError) {
		t.Fatal("fixture bypassed ordinary error mapping", err)
	}
	s, _ := identify(pinned)
	out, err := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "resolve", Input: rows[0].DID, SourceFailure: "fixture.unexpected"})
	if err != nil || out.HasContent || out.SageCode != "record.unreachable" || !strings.Contains(string(out.Metadata), "https://www.w3.org/ns/did#INTERNAL_ERROR") {
		t.Fatal(out, err)
	}
}

func expectedResolutionGate(r report.Report) bool {
	expected := map[string]bool{}
	if r.Profile == "did-1.1" {
		for _, id := range []string{"cid10#verification-methods.9", "cid10#verification-methods.11", "cid10#conformance.2", "did11-cr20260305#production-and-consumption.18", "res10-crd20261001#dereferencing-algorithm-resource.5", "cid10#fragment-resolution.4", "res10-crd20261001#resolving-algorithm.28", "res10-crd20261001#dereferencing-algorithm-resource.11", "res10-crd20261001#resolving-algorithm.29"} {
			expected[id] = true
		}
	}
	actual := r.GateFailures()
	if len(actual) != len(expected) {
		return false
	}
	for _, s := range actual {
		if !expected[s.ID] || s.Verdict != core.Fail {
			return false
		}
	}
	return true
}
