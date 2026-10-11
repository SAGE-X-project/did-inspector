package did11

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

const bindingPrefix = "/1.0/identifiers/"

// Endpoint is the mock's DID resolver HTTP(S) endpoint. Under the fault
// binding-plain-http it is an http URL.
func (m *mock) Endpoint() string {
	if m.on("binding-plain-http") {
		return "http://mock.invalid" + bindingPrefix
	}
	return "https://mock.invalid" + bindingPrefix
}

// Exchange serves the request with the mock's HTTP(S) binding in memory:
// the binding of DID Resolution §12.1 over the mock's own Resolve and
// Dereference, bent by the binding faults.
func (m *mock) Exchange(ctx context.Context, req core.HTTPRequest) (core.HTTPExchange, error) {
	if m.on("binding-exchange-fails") {
		return core.HTTPExchange{}, errMock
	}
	hr := httptest.NewRequestWithContext(ctx, req.Method, m.Endpoint()+req.Target, bytes.NewReader(req.Body))
	hr.Header = req.Header.Clone()
	rec := httptest.NewRecorder()
	m.serveBinding(rec, hr)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	return core.HTTPExchange{
		Method: req.Method, URL: hr.URL.String(), RequestHeader: req.Header.Clone(), RequestBody: req.Body,
		TLS: !m.on("binding-plain-http"), Status: resp.StatusCode, Header: resp.Header, Body: body,
	}, nil
}

var tableStatus = checks.BindingStatus

func (m *mock) serveBinding(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.EscapedPath(), bindingPrefix)
	ident, query := raw, ""
	if strings.HasPrefix(raw, "did%3A") && !m.on("binding-no-decode") {
		ident, _ = url.PathUnescape(raw)
		query = r.URL.RawQuery
	} else if r.URL.RawQuery != "" {
		ident += "?" + r.URL.RawQuery
	}
	opts := map[string]any{}
	if r.Method == http.MethodPost && !m.on("binding-post-ignored") {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			_ = json.Unmarshal(body, &opts)
		}
	}
	if q, _ := url.ParseQuery(query); !m.on("binding-ignore-query") {
		for k := range q {
			switch v := q.Get(k); v {
			case "true", "false":
				opts[k] = v == "true"
			default:
				opts[k] = v
			}
		}
	}
	accept := r.Header.Get("Accept")
	deref := strings.ContainsAny(ident, "/?#") || accept == checks.MediaTypeDIDURLDereferencing
	full := accept == "" || accept == checks.MediaTypeDIDResolution || accept == checks.MediaTypeDIDURLDereferencing
	if !full {
		opts["accept"] = accept
	}
	if deref {
		res, _ := m.Dereference(r.Context(), ident, opts)
		m.writeDereference(w, res, full)
		return
	}
	res, _ := m.Resolve(r.Context(), ident, opts)
	m.writeResolution(w, res, full)
}

func (m *mock) status(md, cm core.DocumentJSON) int {
	if e, ok := md.Get("error"); ok {
		t, _ := e.Get("type")
		if s, ok := tableStatus[t.Str]; ok && !m.on("binding-status-wrong") {
			return s
		}
		return http.StatusInternalServerError + boolInt(m.on("binding-status-wrong"))
	}
	if d, _ := cm.Get("deactivated"); d.Bool && !m.on("binding-no-410") {
		return http.StatusGone
	}
	return http.StatusOK
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (m *mock) writeProblem(w http.ResponseWriter, md core.DocumentJSON, status int) {
	e, _ := md.Get("error")
	data, _ := e.MarshalJSON()
	ct := checks.MediaTypeProblem
	if m.on("binding-problem-plain") {
		ct, data = "text/plain", []byte("error")
	}
	write(w, status, ct, data)
}

func write(w http.ResponseWriter, status int, ct string, body []byte) {
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (m *mock) writeResolution(w http.ResponseWriter, res core.ResolutionResult, full bool) {
	status := m.status(res.ResolutionMetadata, res.DocumentMetadata)
	_, failed := res.ResolutionMetadata.Get("error")
	switch {
	case full || status == http.StatusGone:
		doc := core.Null()
		if res.Document != nil {
			doc = res.Document.Value()
		}
		names := []string{"didDocument", "didResolutionMetadata", "didDocumentMetadata"}
		if m.on("binding-result-shape") {
			names = []string{"document", "metadata", "documentMetadata"}
		}
		body, _ := core.Object(core.M(names[0], doc), core.M(names[1], res.ResolutionMetadata.Value()), core.M(names[2], res.DocumentMetadata.Value())).MarshalJSON()
		write(w, status, checks.MediaTypeDIDResolution, body)
	case failed:
		m.writeProblem(w, res.ResolutionMetadata, status)
	default:
		ct, _ := res.ResolutionMetadata.Get("contentType")
		m.writeRepresentation(w, ct.Str, res.Raw)
	}
}

func (m *mock) writeRepresentation(w http.ResponseWriter, ct string, data []byte) {
	if m.on("binding-content-type-wrong") {
		ct = "application/json"
	}
	if m.on("binding-body-wrapped") {
		data, _ = json.Marshal(map[string]json.RawMessage{"didDocument": data})
	}
	write(w, http.StatusOK, ct, data)
}

func (m *mock) writeDereference(w http.ResponseWriter, res core.DereferenceResult, full bool) {
	status := m.status(res.DereferencingMetadata, res.ContentMetadata)
	_, failed := res.DereferencingMetadata.Get("error")
	switch {
	case full || status == http.StatusGone:
		content := core.Null()
		if len(res.Content) > 0 {
			if v, err := core.ParseJSON(res.Content); err == nil {
				content = v
			} else {
				content = core.String(string(res.Content))
			}
		}
		names := []string{"content", "dereferencingMetadata", "contentMetadata"}
		if m.on("binding-result-shape") {
			names = []string{"result", "metadata", "resultMetadata"}
		}
		body, _ := core.Object(core.M(names[0], content), core.M(names[1], res.DereferencingMetadata.Value()), core.M(names[2], res.ContentMetadata.Value())).MarshalJSON()
		write(w, status, checks.MediaTypeDIDURLDereferencing, body)
	case failed:
		m.writeProblem(w, res.DereferencingMetadata, status)
	case res.MediaType == "text/uri-list" && !m.on("binding-no-303"):
		urls, _ := checks.ParseURIList(res.Content)
		loc := ""
		if len(urls) > 0 {
			loc = urls[0]
		}
		if m.on("binding-location-wrong") {
			loc = "https://wrong.example/"
		}
		w.Header().Set("Location", loc)
		var body []byte
		if m.on("binding-303-body") {
			body = []byte(loc)
		}
		write(w, http.StatusSeeOther, "", body)
	default:
		m.writeRepresentation(w, res.MediaType, res.Content)
	}
}
