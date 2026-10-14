package sage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

type bindingDereferencer struct {
	delegate resolution.Dereferencer
	out      *sageresolution.RoutingBindingResult
	mu       *sync.Mutex
}

func (r bindingDereferencer) Dereference(ctx context.Context, u did.DIDURL, o resolution.DereferenceOptions) resolution.DereferenceResult {
	b, e := json.Marshal(o)
	result := r.delegate.Dereference(ctx, u, o)
	capture, f := dereferenceResult(sageresolution.Result{}, result.DereferencingMetadata, result.ContentStream, result.ContentMetadata)
	call := sageresolution.ClientInvocation{Function: "dereference", Input: u.String(), Options: b, Result: capture}
	if er := errors.Join(e, f); er != nil {
		call.CaptureError = er.Error()
	}
	r.mu.Lock()
	r.out.Native = append(r.out.Native, call)
	r.mu.Unlock()
	return result
}
func (*Subject) InspectRoutingBinding(ctx context.Context, q sageresolution.RoutingRequest, verb string) (sageresolution.RoutingBindingResult, error) {
	out := sageresolution.RoutingBindingResult{Request: q, Method: verb, Role: "owned TLS universal handler with actual root dereferencer and literal example driver; not SAGE registry"}
	if q.Document.MediaType != "application/did" || q.Request.Function != "dereference" {
		return out, errors.New("explicit routing dereference fixture required")
	}
	calls := [][]byte{}
	registry, e := method.NewRegistry(literalRoutingMethod{body: q.Document.Data, calls: &calls})
	if e != nil {
		return out, e
	}
	p := producer.New()
	r, e := resolver.New(registry, consumer.New(), p)
	if e != nil {
		return out, e
	}
	d, e := dereferencer.New(r, p)
	if e != nil {
		return out, e
	}
	var mu sync.Mutex
	observed := bindingDereferencer{d, &out, &mu}
	handler := universal.NewHandler(r, observed, universal.WithPathPrefix(universal.DefaultPathPrefix), universal.WithProducer(p))
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()
	options := map[string]any{}
	for k, v := range q.Request.Options {
		options[k] = v
	}
	if q.Request.Relationship != "" {
		options["verificationRelationship"] = q.Request.Relationship
	}
	request, e := checks.BindingRequest(verb, q.Request.Input, q.Request.Accept, options)
	if e != nil {
		return out, e
	}
	httpRequest, e := http.NewRequestWithContext(ctx, request.Method, srv.URL+universal.DefaultPathPrefix+request.Target, nil)
	if e != nil {
		return out, e
	}
	httpRequest.Header = request.Header.Clone()
	if len(request.Body) > 0 {
		httpRequest.Body = io.NopCloser(bytes.NewReader(request.Body))
	}
	hc := srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := hc.Do(httpRequest)
	if e != nil {
		return out, e
	}
	defer func() { _ = response.Body.Close() }()
	body, e := io.ReadAll(response.Body)
	if e != nil {
		return out, e
	}
	mu.Lock()
	defer mu.Unlock()
	out.Exchange = core.HTTPExchange{Method: request.Method, URL: httpRequest.URL.String(), RequestHeader: request.Header.Clone(), RequestBody: request.Body, TLS: response.TLS != nil, Status: response.StatusCode, Header: response.Header.Clone(), Body: body}
	return out, nil
}
