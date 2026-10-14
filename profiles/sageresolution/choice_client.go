package sageresolution

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const proxyChoiceID = "res10-crd20261001#resolver-architectures-proxied.1"
const ipCertificateChoiceID = "res10-crd20261001#bindings-https.3"

func proxyChoiceFixture(record sageprojection.Record, post bool) clientFixture {
	return clientFixture{Statements: []string{proxyChoiceID}, Record: record, Request: ClientRequest{Request: Request{Function: "resolve", Input: record.DID}, Post: post}}
}
func judgeProxyChoice(f clientFixture, out ClientResult, input string) []core.Observation {
	obs := judgeClient(f, out, input)
	// Retain the actual wire and nested resolver invocation contracts. Successful
	// proxy use does not establish all steps of the resolution algorithm.
	result := obs[0]
	result.Statement = proxyChoiceID
	result.Detail = "Actual selected downstream Client invokes an owned upstream SAGE resolver using its explicit public fixture Source. GET/POST input/options, native invocation and returned identity are independently checked. Only this chosen proxy invocation is established; upstream authority, every algorithm step and deployed proxy behavior are not established."
	return []core.Observation{result}
}
func judgeIPCertificateChoice(values []TrustResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{ipCertificateChoiceID}, core.Error, "Actual universal Client connecting to an owned IP-address TLS endpoint. Peer certificate bytes and verified TLS channel are checked independently. Other certificate naming choices and operational PKI are not established.", input, values)
	if len(values) != 2 {
		return obs
	}
	cert, err := x509.ParseCertificate(values[0].ServerCertificate)
	if err != nil {
		return obs
	}
	endpoint, err := url.Parse(values[0].Endpoint)
	if err != nil {
		return obs
	}
	good, bad := values[0], values[1]
	ip := net.ParseIP(endpoint.Hostname())
	if good.Role != "actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim" || good.CaptureError != "" || good.ClientMissing || !bad.ClientMissing || endpoint.Scheme != "https" || endpoint.Path != "/1.0/identifiers/" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil || ip == nil || !ip.IsLoopback() {
		return obs
	}
	obs[0].Verdict = core.Fail
	if good.ServerVerified && bytes.Equal(good.ServerPeer, good.ServerCertificate) && cert.VerifyHostname(endpoint.Hostname()) == nil {
		obs[0].Verdict = core.Pass
	}
	// Client authentication and application acceptance are separate predicates;
	// the missing-client-identity call is retained as a diagnostic only.
	obs[0].Expected = "Actual verified TLS peer certificate covers the chosen loopback IP address; no DNS identifier is needed for this connection"
	return obs
}
func appendChoiceClientCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	record := records[0]
	for _, post := range []bool{false, true} {
		f := proxyChoiceFixture(record, post)
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/choice-proxy-post-%t", p.Name, post), Profile: p.Name, Statements: []string{proxyChoiceID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			subject, ok := target.(ClientSubject)
			if !ok {
				return libraryUnavailable([]string{proxyChoiceID}, core.NotSupported, "no actual client observer", string(input), nil)
			}
			out, err := subject.InspectClient(ctx, f.Record, f.Request)
			if err != nil {
				return libraryUnavailable([]string{proxyChoiceID}, core.Error, err.Error(), string(input), out)
			}
			return judgeProxyChoice(f, out, string(input))
		}})
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/choice-ip-certificate", Profile: p.Name, Statements: []string{ipCertificateChoiceID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		input, _ := json.Marshal(record)
		subject, ok := target.(TrustSubject)
		if !ok {
			return libraryUnavailable([]string{ipCertificateChoiceID}, core.NotSupported, "no actual TLS certificate observer", string(input), nil)
		}
		values := []TrustResult{}
		for _, missing := range []bool{false, true} {
			v, err := subject.InspectTrust(ctx, record, missing)
			values = append(values, v)
			if err != nil {
				return libraryUnavailable([]string{ipCertificateChoiceID}, core.Error, err.Error(), string(input), values)
			}
		}
		return judgeIPCertificateChoice(values, string(input))
	}})
}
