package sage

import (
	"context"
	"encoding/json"
	"errors"
	didsage "github.com/sage-x-project/did-go/advanced/sage"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
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

type clientResolver struct {
	delegate *didsage.Resolver
	mu       *sync.Mutex
	calls    *[]sageresolution.ClientInvocation
}

func (r clientResolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	data, e := json.Marshal(opts)
	result := r.delegate.Resolve(ctx, d, opts)
	capture := sageresolution.Result{HasContent: result.Document != nil, Raw: result.Raw}
	if result.Document != nil {
		capture.ReturnedID = result.Document.ID().String()
		capture.ContentKind = "document"
		var err error
		capture.Snapshot, err = documentSnapshot(result.Document)
		if err != nil {
			e = errors.Join(e, err)
		}
	}
	capture, f := nativeResult(capture, result.ResolutionMetadata, result.DocumentMetadata)
	call := sageresolution.ClientInvocation{Function: "resolve", Input: d.String(), Options: data, Result: capture}
	if err := errors.Join(e, f); err != nil {
		call.CaptureError = err.Error()
	}
	r.mu.Lock()
	*r.calls = append(*r.calls, call)
	r.mu.Unlock()
	return result
}
func (r clientResolver) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	data, e := json.Marshal(opts)
	result := r.delegate.Dereference(ctx, u, opts)
	capture, f := dereferenceResult(sageresolution.Result{}, result.DereferencingMetadata, result.ContentStream, result.ContentMetadata)
	call := sageresolution.ClientInvocation{Function: "dereference", Input: u.String(), Options: data, Result: capture}
	if err := errors.Join(e, f); err != nil {
		call.CaptureError = err.Error()
	}
	r.mu.Lock()
	*r.calls = append(*r.calls, call)
	r.mu.Unlock()
	return result
}

// InspectClient passively captures the unchanged selected Client's request,
// consumer calls and output. Only the owned loopback server is contacted.
func (*Subject) InspectClient(ctx context.Context, in sageprojection.Record, q sageresolution.ClientRequest) (sageresolution.ClientResult, error) {
	out := sageresolution.ClientResult{Operation: "github.com/sage-x-project/did-go/resolution/universal.Client." + q.Request.Function, Request: q, ServerRole: "universal handler with SAGE resolver and explicit fixture Source"}
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
	var serverMu sync.Mutex
	nativeCalls := []sageresolution.ClientInvocation{}
	observed := clientResolver{resolver, &serverMu, &nativeCalls}
	var handler http.Handler = universal.NewHandler(observed, observed, universal.WithPathPrefix(universal.DefaultPathPrefix), universal.WithProducer(producer.New()))
	if len(q.Reply) > 0 {
		out.ServerRole = "controlled client response fixture; not SAGE server output"
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/did-resolution")
			_, _ = w.Write(q.Reply)
		})
	}
	serverCalls := 0
	serverTLS := false
	captureServer := func() {
		serverMu.Lock()
		defer serverMu.Unlock()
		out.ServerCalls = serverCalls
		out.ServerTLS = serverTLS
		out.Native = append([]sageresolution.ClientInvocation{}, nativeCalls...)
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
