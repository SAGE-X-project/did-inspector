package sage

import (
	"context"
	"errors"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

type clientTransport struct {
	delegate http.RoundTripper
	calls    *[]sageresolution.ClientWire
}

func (t clientTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	x := sageresolution.ClientWire{URL: q.URL.String(), Method: q.Method, Accept: q.Header.Get("Accept"), ContentType: q.Header.Get("Content-Type")}
	if q.GetBody != nil {
		reader, e := q.GetBody()
		if e != nil {
			x.CaptureError = e.Error()
		} else {
			body, e := io.ReadAll(reader)
			x.Body = body
			_ = reader.Close()
			if e != nil {
				x.CaptureError = e.Error()
			}
		}
	} else if q.Body != nil && q.Body != http.NoBody {
		x.CaptureError = "request body cannot be captured independently"
	}
	*t.calls = append(*t.calls, x)
	return t.delegate.RoundTrip(q)
}

// InspectClient passively captures the unchanged selected Client's request,
// consumer calls and output. Only the owned loopback server is contacted.
func (*Subject) InspectClient(ctx context.Context, in sageprojection.Record, q sageresolution.ClientRequest) (sageresolution.ClientResult, error) {
	out := sageresolution.ClientResult{Operation: "github.com/sage-x-project/did-go/resolution/universal.Client." + q.Request.Function, Request: q, ServerRole: "SAGE handler with explicit fixture Source"}
	if q.Request.Function != "resolve" && q.Request.Function != "dereference" {
		return out, errors.New("unknown client operation")
	}
	rec, e := resolutionRecord(in)
	if e != nil {
		return out, e
	}
	resolver, e := didsage.NewResolver(resolutionSource{rec, ""}, consumer.New(), producer.New())
	if e != nil {
		return out, e
	}
	var handler http.Handler = didsage.NewHandler(resolver, universal.DefaultPathPrefix, universal.WithProducer(producer.New()))
	if len(q.Reply) > 0 {
		out.ServerRole = "controlled client response fixture; not SAGE server output"
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/did-resolution")
			_, _ = w.Write(q.Reply)
		})
	}
	var serverMu sync.Mutex
	serverCalls := 0
	serverTLS := false
	captureServer := func() {
		serverMu.Lock()
		defer serverMu.Unlock()
		out.ServerCalls = serverCalls
		out.ServerTLS = serverTLS
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverMu.Lock()
		serverCalls++
		serverTLS = r.TLS != nil
		serverMu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	out.Endpoint = srv.URL + universal.DefaultPathPrefix
	hc := srv.Client()
	hc.Transport = clientTransport{hc.Transport, &out.Wire}
	client, e := universal.NewClient(out.Endpoint, hc, observedConsumer{consumer.New(), &out.Consumer}, universal.WithPOST(q.Post))
	if e != nil {
		return out, e
	}
	ro, do := nativeOptions(q.Request)
	if q.Request.Function == "resolve" {
		d, e := did.Parse(q.Request.Input)
		if e != nil {
			return out, e
		}
		r := client.Resolve(ctx, d, ro)
		captureServer()
		native := sageresolution.Result{Raw: r.Raw, HasContent: r.Document != nil}
		if r.Document != nil {
			native.ReturnedID = r.Document.ID().String()
			native.ContentKind = "document"
			native.Snapshot, e = documentSnapshot(r.Document)
			if e != nil {
				return out, e
			}
		}
		out.Result, e = nativeResult(native, r.ResolutionMetadata, r.DocumentMetadata)
		return out, e
	}
	u, e := did.ParseURL(q.Request.Input)
	if e != nil {
		return out, e
	}
	r := client.Dereference(ctx, u, do)
	captureServer()
	out.Result, e = dereferenceResult(sageresolution.Result{}, r.DereferencingMetadata, r.ContentStream, r.ContentMetadata)
	return out, e
}
