package sageresolution

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func TestProxyChoiceInputsAndIdentity(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, post := range []bool{false, true} {
		f := proxyChoiceFixture(records[0], post)
		v := clientControl(f)
		if judgeProxyChoice(f, v, "input")[0].Verdict != core.Pass {
			t.Fatal("valid proxy")
		}
		v.Native[0].Input = "did:example:other"
		if judgeProxyChoice(f, v, "input")[0].Verdict == core.Pass {
			t.Fatal("wrong upstream invocation")
		}
	}
}
func TestIPCertificateChoice(t *testing.T) {
	good := trustControl(t)
	if judgeIPCertificateChoice(good, "input")[0].Verdict != core.Pass {
		t.Fatal("IP certificate")
	}
	if judgeIPCertificateChoice(nil, "input")[0].Verdict != core.Error {
		t.Fatal("missing evidence")
	}
	for _, change := range []func(*TrustResult){func(v *TrustResult) { v.ServerCertificate = nil }, func(v *TrustResult) { v.Endpoint = "https://%/" }, func(v *TrustResult) { v.Role = "unknown" }} {
		v := trustControl(t)
		change(&v[0])
		if judgeIPCertificateChoice(v, "input")[0].Verdict != core.Error {
			t.Fatal("invalid certificate evidence")
		}
	}
	good = trustControl(t)
	good[0].Endpoint = "https://127.0.0.2:443/1.0/identifiers/"
	if judgeIPCertificateChoice(good, "input")[0].Verdict != core.Fail {
		t.Fatal("wrong SAN")
	}
	good = trustControl(t)
	good[0].ClientVerified = false
	good[1].ClientResult.Metadata = []byte("invalid diagnostic")
	if judgeIPCertificateChoice(good, "input")[0].Verdict != core.Pass {
		t.Fatal("client authentication incorrectly controls IP certificate choice")
	}
	good = trustControl(t)
	good[0].ServerVerified = false
	if judgeIPCertificateChoice(good, "input")[0].Verdict != core.Fail {
		t.Fatal("unverified server")
	}
}
func TestChoiceClientDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-core-1.0"}
	appendChoiceClientCases(&p, records)
	if len(p.Cases) != 0 {
		t.Fatal("wrong profile")
	}
	p.Name = "did-1.1"
	appendChoiceClientCases(&p, records)
	if len(p.Cases) != 3 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Statements[0] == proxyChoiceID {
			for _, tt := range []struct {
				s    core.Subject
				want core.Verdict
			}{{clientMock{fail: false}, core.Pass}, {clientMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want {
						t.Fatal(c.ID, o)
					}
				}
			}
		} else {
			for _, tt := range []struct {
				s    core.Subject
				want core.Verdict
			}{{&trustMock{values: trustControl(t)}, core.Pass}, {&trustMock{values: trustControl(t), failAt: 1}, core.Error}, {&trustMock{values: trustControl(t), failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want {
						t.Fatal(c.ID, o)
					}
				}
			}
		}
	}
}
