package sageresolution

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"net"
	"net/url"
)

func judgeTrust(values []TrustResult, input string) []core.Observation {
	ids := []string{"res10-crd20261001#resolver-architectures.1", "res10-crd20261001#resolver-architectures.2"}
	out := libraryUnavailable(ids, core.Error, "Actual selected universal Client and owned self-hosted loopback SAGE handler with explicit public Source. Fixed trust anchors and peer-certificate equality plus both TLS verified chains are observed. An omitted client certificate is a normal owned authorization refusal control, not an exploit. No external resolver, operational registry authority, real deployment, application key custody or transport-bypass code is used. Only fixture-controlled mutual TLS configuration and client behavior are established.", input, values)
	if len(values) != 2 {
		return out
	}
	good, bad := values[0], values[1]
	for _, v := range values {
		u, e := url.Parse(v.Endpoint)
		if e != nil || u.Scheme != "https" || u.Path != "/1.0/identifiers/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || v.Role != "actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim" || v.CaptureError != "" {
			return out
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return out
		}
		if _, e := x509.ParseCertificate(v.ServerCertificate); e != nil {
			return out
		}
		if _, e := x509.ParseCertificate(v.ClientCertificate); e != nil {
			return out
		}
	}
	if good.ClientMissing || !bad.ClientMissing {
		return out
	}
	// Trust selection and the channel have independent normative predicates.
	trusted := good.ServerVerified && bytes.Equal(good.ServerPeer, good.ServerCertificate)
	channel := trusted && good.HTTPCalls == 1 && good.ClientVerified && good.TLSVersion >= tls.VersionTLS12 && bytes.Equal(good.ClientPeer, good.ClientCertificate)
	badMD, e := parse(bad.ClientResult.Metadata)
	if e != nil {
		return out
	}
	channel = channel && bad.HTTPCalls == 0 && !bad.ClientVerified && !bad.ClientResult.HasContent && nativeErrorDescriptor(badMD)
	predicates := []bool{trusted, channel}
	for i := range out {
		out[i].Verdict = core.Fail
		if predicates[i] {
			out[i].Verdict = core.Pass
		}
		out[i].Expected = "Explicit owned resolver trust anchor and authenticated TLS channel, judged independently of document processing"
	}
	return out
}
func appendTrustCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	r := records[0]
	ids := []string{"res10-crd20261001#resolver-architectures.1", "res10-crd20261001#resolver-architectures.2"}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-trust-mutual-tls", Profile: p.Name, Statements: ids, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		input, _ := json.Marshal(struct {
			Record sageprojection.Record `json:"record"`
			Mode   string                `json:"mode"`
		}{r, "owned self-hosted mutual TLS; present and missing ephemeral client identity"})
		values := []TrustResult{}
		s, ok := target.(TrustSubject)
		if !ok {
			return libraryUnavailable(ids, core.NotSupported, "no owned trusted-client observer", string(input), values)
		}
		for _, missing := range []bool{false, true} {
			v, e := s.InspectTrust(ctx, r, missing)
			values = append(values, v)
			if e != nil {
				return libraryUnavailable(ids, core.Error, e.Error(), string(input), values)
			}
		}
		return judgeTrust(values, string(input))
	}})
}
