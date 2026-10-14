package sage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

func fixtureClientCertificate(entropy io.Reader) (tls.Certificate, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, e := io.ReadFull(entropy, seed); e != nil {
		return tls.Certificate{}, e
	}
	key := ed25519.NewKeyFromSeed(seed)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-loopback-client-fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(entropy, template, template, key.Public(), key)
	if e != nil {
		return tls.Certificate{}, e
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, nil
}

// InspectTrust configures the actual selected universal Client for owned mTLS.
// The ephemeral fixture credential exists only in memory and is never reported.
func (*Subject) InspectTrust(ctx context.Context, in sageprojection.Record, missing bool) (sageresolution.TrustResult, error) {
	out := sageresolution.TrustResult{Role: "actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim", ClientMissing: missing}
	rec, e := resolutionRecord(in)
	if e != nil {
		return out, e
	}
	r, e := sage.NewResolver(resolutionSource{rec, ""}, consumer.New(), producer.New())
	if e != nil {
		return out, e
	}
	certificate, e := fixtureClientCertificate(rand.Reader)
	if e != nil {
		return out, e
	}
	out.ClientCertificate = append([]byte(nil), certificate.Certificate[0]...)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	var mu sync.Mutex
	handler := universal.NewHandler(r, r, universal.WithPathPrefix(universal.DefaultPathPrefix), universal.WithProducer(producer.New()))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		mu.Lock()
		out.HTTPCalls++
		if q.TLS != nil {
			out.TLSVersion = q.TLS.Version
			out.ClientVerified = len(q.TLS.VerifiedChains) > 0
			if len(q.TLS.PeerCertificates) > 0 {
				out.ClientPeer = append([]byte(nil), q.TLS.PeerCertificates[0].Raw...)
			}
		}
		mu.Unlock()
		handler.ServeHTTP(w, q)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	out.Endpoint = srv.URL + universal.DefaultPathPrefix
	out.ServerCertificate = append([]byte(nil), srv.Certificate().Raw...)
	hc := srv.Client()
	transport := hc.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	if !missing {
		transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	}
	transport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		mu.Lock()
		defer mu.Unlock()
		out.ServerVerified = len(state.VerifiedChains) > 0
		if len(state.PeerCertificates) > 0 {
			out.ServerPeer = append([]byte(nil), state.PeerCertificates[0].Raw...)
		}
		if !out.ServerVerified || !bytes.Equal(out.ServerPeer, out.ServerCertificate) {
			return errors.New("unexpected owned fixture server identity")
		}
		return nil
	}
	hc.Transport = transport
	defer transport.CloseIdleConnections()
	client, e := universal.NewClient(out.Endpoint, hc, consumer.New())
	if e != nil {
		return out, e
	}
	d, e := did.Parse(in.DID)
	if e != nil {
		return out, e
	}
	result := client.Resolve(ctx, d, resolution.ResolutionOptions{Accept: "application/did"})
	mu.Lock()
	defer mu.Unlock()
	capture := sageresolution.Result{HasContent: result.Document != nil, Raw: result.Raw}
	if result.Document != nil {
		capture.ReturnedID = result.Document.ID().String()
		capture.ContentKind = "document"
		capture.Snapshot, e = documentSnapshot(result.Document)
		if e != nil {
			return out, e
		}
	}
	out.ClientResult, e = nativeResult(capture, result.ResolutionMetadata, result.DocumentMetadata)
	if e != nil {
		return out, e
	}
	return out, nil
}
