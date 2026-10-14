package sage

import (
	"crypto/rand"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"io"
	"strings"
	"testing"
)

func TestActualOwnedMutualTLS(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-trust-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				t.Fatal(o.Statement, o.Verdict, o.Observed)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
func TestTrustAdapterRejectsUncapturableRecord(t *testing.T) {
	s, _ := identify(pinned)
	if _, e := s.InspectTrust(t.Context(), sageprojection.Record{DID: "bad"}, false); e == nil {
		t.Fatal("invalid record")
	}
}

func TestFixtureCertificateEntropyFailure(t *testing.T) {
	for _, limit := range []int64{0, 1, 16, 31} {
		if _, e := fixtureClientCertificate(io.LimitReader(rand.Reader, limit)); e == nil {
			t.Fatalf("short entropy reader %d accepted", limit)
		}
	}
	certificate, e := fixtureClientCertificate(rand.Reader)
	if e != nil || certificate.Leaf == nil || len(certificate.Certificate) != 1 {
		t.Fatal("valid in-memory fixture certificate", e)
	}
}
