package sage

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func TestNativeOptionTranslationPreservesValues(t *testing.T) {
	opts := map[string]any{"accept": "application/did", "expandRelativeUrls": true, "noCache": true, "versionId": "7", "versionTime": "2026-01-01T00:00:00.1+09:00", "verificationRelationship": "authentication", "unconfiguredExtension": "original"}
	before, _ := json.Marshal(opts)
	ro, do := nativeOptions(sageresolution.Request{Accept: "text/html", Relationship: "keyAgreement", Options: opts})
	if ro.Accept != "application/did" || !ro.ExpandRelativeURLs || !ro.NoCache || ro.VersionID != "7" || ro.VersionTime == nil {
		t.Fatal("lost typed options", ro)
	}
	_, offset := ro.VersionTime.Zone()
	if offset != 9*60*60 || ro.VersionTime.Nanosecond() != 100000000 {
		t.Fatal("time normalized")
	}
	if do.Accept != "application/did" || do.VerificationRelationship != "authentication" || do.Extra["versionTime"] != opts["versionTime"] {
		t.Fatal("dereference translation", do)
	}
	if ro.Extra["unconfiguredExtension"] != "original" {
		t.Fatal("unknown option dropped")
	}
	after, _ := json.Marshal(opts)
	if string(before) != string(after) {
		t.Fatal("original input mutated")
	}
	ro, do = nativeOptions(sageresolution.Request{Options: map[string]any{"accept": 7, "verificationRelationship": false}})
	if ro.Extra["accept"] != 7 || do.Extra["accept"] != 7 || do.Extra["verificationRelationship"] != false {
		t.Fatal("wrong types repaired")
	}
	for _, value := range []any{7, "bad", "2026-01-01T00:00:00.0000000001Z", "2026-01-01T00:00:00,1Z"} {
		ro, _ = nativeOptions(sageresolution.Request{Options: map[string]any{"versionTime": value}})
		if ro.VersionTime != nil || ro.Extra["versionTime"] != value {
			t.Fatal("original time lost", value)
		}
	}
	for _, name := range []string{"accept", "expandRelativeUrls", "noCache", "versionId"} {
		ro, _ = nativeOptions(sageresolution.Request{Options: map[string]any{name: []any{1}}})
		if ro.Extra[name] == nil {
			t.Fatal("wrong type dropped", name)
		}
	}
	ro, _ = nativeOptions(sageresolution.Request{Options: map[string]any{"versionTime": "2026-01-01T00:00:00Z"}})
	if ro.VersionTime == nil || ro.VersionTime.Format(time.RFC3339) != "2026-01-01T00:00:00Z" {
		t.Fatal("valid timestamp")
	}
}
func TestActualInvalidOptionsAndTransportRefusals(t *testing.T) {
	s, _ := identify(pinned)
	rows, _ := sageprojection.Fixtures()
	id := rows[0].DID
	for _, bad := range []any{7, "2026-01-01T00:00:00.0000000001Z", "2026-01-01T00:00:00,1Z"} {
		out, e := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "resolve", Input: id, Options: map[string]any{"versionTime": bad}})
		if e != nil || out.HasContent || !strings.Contains(string(out.Metadata), "#INVALID_OPTIONS") {
			t.Fatal("invalid time accepted", bad, e, out)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, options := range []map[string]any{{"expandRelativeUrls": "wrong"}, {"versionTime": "2026-01-01T00:00:00.1Z"}, {"versionTime": "2026-01-01T00:00:00+09:00"}} {
			req, e := checks.BindingRequest(method, id, checks.MediaTypeDIDResolution, options)
			if e != nil {
				t.Fatal(e)
			}
			out, e := s.InspectResolution(t.Context(), rows[0], sageresolution.Request{Function: "http", Input: id, Options: options, HTTP: &req})
			if e != nil || out.Exchange == nil || !out.Exchange.TLS || out.Exchange.Status != 400 {
				t.Fatal("transport refusal", method, e, out)
			}
			_, kind, e := checks.BindingError(*out.Exchange)
			if e != nil || kind != "https://www.w3.org/ns/did#INVALID_OPTIONS" {
				t.Fatal("transport error", e, kind)
			}
		}
	}
}
