package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"net/url"
	"reflect"
	"strings"
)

type clientFixture struct {
	Name       string                `json:"name"`
	Record     sageprojection.Record `json:"record"`
	Request    ClientRequest         `json:"request"`
	Statements []string              `json:"statements"`
}

func clientIDs(numbers ...int) []string {
	out := []string{}
	for _, n := range numbers {
		out = append(out, fmt.Sprintf("res10-crd20261001#bindings-https.%d", n))
	}
	return out
}
func clientFixtures(record sageprojection.Record) []clientFixture {
	rows := []clientFixture{}
	for _, function := range []string{"resolve", "dereference"} {
		for _, post := range []bool{false, true} {
			for _, direct := range []bool{false, true} {
				for _, options := range []bool{false, true} {
					q := ClientRequest{Request: Request{Function: function, Input: record.DID}, Post: post}
					ids := clientIDs(4)
					if function == "resolve" {
						ids = append(ids, clientIDs(5, 6)...)
						if direct {
							q.Request.Accept = "application/did"
							ids = append(ids, clientIDs(8)...)
						} else {
							ids = append(ids, clientIDs(7)...)
						}
						if options {
							q.Request.Options = map[string]any{"noCache": true}
						}
					} else {
						q.Request.Input += "#sign"
						ids = append(ids, clientIDs(9, 10)...)
						if direct {
							q.Request.Accept = "application/json"
							ids = append(ids, clientIDs(12)...)
						} else {
							ids = append(ids, clientIDs(11)...)
						}
						if options {
							q.Request.Options = map[string]any{"verificationRelationship": "authentication"}
						}
					}
					if post {
						ids = append(ids, clientIDs(18, 21)...)
						if options {
							ids = append(ids, clientIDs(19, 20)...)
						}
					} else {
						ids = append(ids, clientIDs(13, 17)...)
						if options {
							ids = append(ids, clientIDs(14, 15, 16)...)
						}
					}
					rows = append(rows, clientFixture{Name: fmt.Sprintf("%s-post-%t-direct-%t-options-%t", function, post, direct, options), Record: record, Request: q, Statements: ids})
				}
			}
		}
	}
	for _, media := range []string{"application/did", "application/did+json"} {
		body := `{"didResolutionMetadata":{"contentType":"` + media + `"},"didDocument":{"id":"` + record.DID + `"},"didDocumentMetadata":{}}`
		rows = append(rows, clientFixture{Name: "metadata-media-" + strings.TrimPrefix(media, "application/"), Record: record, Request: ClientRequest{Request: Request{Function: "resolve", Input: record.DID}, Reply: []byte(body)}, Statements: []string{"res10-crd20261001#did-resolution-metadata.4"}})
	}
	return rows
}

// percentIdentifier uses the literal RFC3986 unreserved byte set, independent
// of the subject's URL encoder. It does not normalize the original DID URL.
func percentIdentifier(text string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&15])
		}
	}
	return out.String()
}
func clientWireVerdict(f clientFixture, out ClientResult) core.Verdict {
	q := f.Request
	if out.Operation != "github.com/sage-x-project/did-go/resolution/universal.Client."+q.Request.Function || !reflect.DeepEqual(out.Request, q) || len(out.Wire) != 1 || out.ServerCalls != 1 || !out.ServerTLS {
		return core.Error
	}
	ep, e := url.Parse(out.Endpoint)
	if e != nil || ep.Scheme != "https" || !strings.HasPrefix(ep.Host, "127.0.0.1:") || ep.Path != "/1.0/identifiers/" || ep.RawQuery != "" || ep.Fragment != "" || ep.User != nil {
		return core.Error
	}
	wire := out.Wire[0]
	u, e := url.Parse(wire.URL)
	if e != nil || wire.CaptureError != "" {
		return core.Error
	}
	method := "GET"
	if q.Post {
		method = "POST"
	}
	accept := q.Request.Accept
	if accept == "" {
		accept = "application/did-resolution"
		if q.Request.Function == "dereference" {
			accept = "application/did-url-dereferencing"
		}
	}
	ident := q.Request.Input
	if (!q.Post && len(q.Request.Options) > 0) || strings.ContainsAny(ident, "?#%") {
		ident = percentIdentifier(ident)
	}
	if wire.Method != method || wire.Accept != accept || u.Scheme != ep.Scheme || u.Host != ep.Host || u.EscapedPath() != ep.EscapedPath()+ident || u.Fragment != "" || u.User != nil {
		return core.Fail
	}
	if q.Post {
		if u.RawQuery != "" {
			return core.Fail
		}
		if len(q.Request.Options) > 0 {
			var body map[string]any
			if json.Unmarshal(wire.Body, &body) != nil || !reflect.DeepEqual(body, q.Request.Options) || wire.ContentType != "application/json" {
				return core.Fail
			}
		} else if len(wire.Body) > 0 || wire.ContentType != "" {
			return core.Fail
		}
	} else {
		if len(wire.Body) > 0 || wire.ContentType != "" {
			return core.Fail
		}
		params, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return core.Fail
		}
		if len(params) != len(q.Request.Options) {
			return core.Fail
		}
		for k, v := range q.Request.Options {
			values := params[k]
			if len(values) != 1 || values[0] != fmt.Sprint(v) {
				return core.Fail
			}
		}
	}
	if len(q.Reply) > 0 {
		if out.ServerRole != "controlled client response fixture; not SAGE server output" || len(out.Consumer) != 1 || len(out.Native) != 0 {
			return core.Error
		}
		var reply struct {
			Metadata struct {
				ContentType string `json:"contentType"`
			} `json:"didResolutionMetadata"`
			Document json.RawMessage `json:"didDocument"`
		}
		if json.Unmarshal(q.Reply, &reply) != nil {
			return core.Error
		}
		c := out.Consumer[0]
		version := "1.1"
		if reply.Metadata.ContentType == "application/did+json" {
			version = "1.0"
		}
		var actual, want any
		e = json.Unmarshal(c.Input, &actual)
		err := json.Unmarshal(reply.Document, &want)
		if c.Operation != pipelineConsumer || c.CaptureError != "" || c.Error != "" || c.MediaType != reply.Metadata.ContentType || c.Version != version || e != nil || err != nil || !reflect.DeepEqual(actual, want) || !out.Result.HasContent || out.Result.ReturnedID != q.Request.Input {
			return core.Fail
		}
	} else {
		if out.ServerRole != "universal handler with SAGE resolver and explicit fixture Source" || len(out.Native) != 1 {
			return core.Error
		}
		native := out.Native[0]
		expected := map[string]any{}
		for k, v := range q.Request.Options {
			expected[k] = v
		}
		if q.Request.Accept != "" {
			expected["accept"] = q.Request.Accept
		}
		var options map[string]any
		if json.Unmarshal(native.Options, &options) != nil || native.CaptureError != "" {
			return core.Error
		}
		if native.Function != q.Request.Function || native.Input != q.Request.Input || !reflect.DeepEqual(options, expected) || !native.Result.HasContent || !out.Result.HasContent {
			return core.Fail
		}
		expectedID := q.Request.Input
		if native.Result.ReturnedID != expectedID || out.Result.ReturnedID != expectedID {
			return core.Fail
		}
	}
	return core.Pass
}
func judgeClient(f clientFixture, out ClientResult, input string) []core.Observation {
	v := clientWireVerdict(f, out)
	raw, _ := json.Marshal(out)
	obs := unavailable(f.Statements, v, "Actual pinned universal.Client constructs and executes one request against an owned TLS endpoint. Passive request, actual resolver/dereferencer invocation and consumer captures and actual results are archived. Sixteen branch controls cover GET/POST, resolution/dereferencing, full/direct response choice and non-accept options. Controlled media contrasts prove client parsing only, not SAGE server output. No production trust, mutual TLS, authority or entire internal algorithm trace is established.")
	for i := range obs {
		obs[i].Input = input
		obs[i].Observed = string(raw)
		obs[i].Expected = "Actual client method/endpoint/identifier, Accept header and independent query/JSON option contract, or literal metadata-directed consumer call"
	}
	return obs
}
func appendClientCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range clientFixtures(rows[0]) {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/library-client-" + f.Name, Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(ClientSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no actual client observer", string(input), nil)
			}
			out, e := s.InspectClient(ctx, f.Record, f.Request)
			if e != nil {
				return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
			}
			return judgeClient(f, out, string(input))
		}})
	}
}
