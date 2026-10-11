package core10

import (
	"errors"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// mock is a test subject that behaves as DID Core 1.0 requires on the
// profile's fixtures, unless a fault switches one behavior to a violation.
// It lives only in tests: it shows that each case gives PASS for a
// conforming subject and FAIL for a violating one. Its document checks use
// an answer key built from documents.json; its §7 functions follow DID Core
// 1.0 with keyword errors.
type mock struct {
	faults map[string]bool
	reg    *fixtures.Registry
	valid  map[string]bool
}

var errMock = errors.New("mock: rejected")

func newMock(faults ...string) *mock {
	m := &mock{faults: map[string]bool{}, valid: answerKey()}
	for _, f := range faults {
		m.faults[f] = true
	}
	return m
}

func answerKey() map[string]bool {
	key := map[string]bool{}
	for _, g := range LoadFixtures().Documents.Groups {
		for _, f := range g.Valid {
			if f.MediaType == "" {
				key[string(f.Bytes())] = true
			}
		}
		for _, f := range g.Invalid {
			if f.MediaType == "" {
				key[string(f.Bytes())] = false
			}
		}
	}
	return key
}

func (m *mock) on(f string) bool { return m.faults[f] }

func (m *mock) conforms(data []byte) bool {
	ok, known := m.valid[string(data)]
	return !known || ok
}

func (m *mock) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "core10-mock", Version: "0", Revision: "test"}
}

func (m *mock) Supports(_ string, c core.Capability) bool { return !m.on("unsupported:" + string(c)) }

func (m *mock) LoadFixtureRegistry(r *fixtures.Registry) error {
	if m.on("registry-load-fails") {
		return errMock
	}
	m.reg = r
	return nil
}

func (m *mock) ParseDID(s string) (core.DIDParts, error) {
	switch {
	case m.on("parser-rejects-all"):
		return core.DIDParts{}, errMock
	case m.on("parser-accepts-all"):
		parts := strings.SplitN(s+"::", ":", 3)
		return core.DIDParts{DID: s, Method: parts[1], MethodSpecificID: strings.TrimSuffix(parts[2], "::")}, nil
	}
	p, err := checks.ParseDID(s)
	if m.on("parser-wrong-parts") {
		p.Method, p.MethodSpecificID = p.MethodSpecificID, p.Method
	}
	return p, err
}

func (m *mock) ParseDIDURL(s string) (core.DIDURLParts, error) {
	switch {
	case m.on("parser-rejects-all"):
		return core.DIDURLParts{}, errMock
	case m.on("parser-accepts-all"):
		return core.DIDURLParts{DIDURL: s}, nil
	}
	u, err := checks.ParseDIDURL(s)
	if m.on("parser-wrong-parts") {
		u.Path, u.Fragment = u.Fragment, u.Path
	}
	return u, err
}

func (m *mock) Consume(data []byte, mediaType, requireVersion string, _ bool) (core.DocumentJSON, core.ConsumeInfo, error) {
	mt := checks.MediaTypeEssence(mediaType)
	switch {
	case m.on("consumer-rejects-all"):
		return core.DocumentJSON{}, core.ConsumeInfo{}, errMock
	case mt != MediaTypeJSON && mt != MediaTypeJSONLD && !m.on("consumer-ignores-media-type"):
		return core.DocumentJSON{}, core.ConsumeInfo{}, errors.New("mock: not a DID Core 1.0 media type")
	}
	doc, err := core.ParseDocumentJSON(data)
	accept := m.on("consumer-accepts-all")
	if err != nil && !accept {
		return core.DocumentJSON{}, core.ConsumeInfo{}, err
	}
	if _, has := doc.Get("@context"); mt == MediaTypeJSONLD && !has && !accept {
		return core.DocumentJSON{}, core.ConsumeInfo{}, errors.New("mock: JSON-LD without @context")
	}
	if !m.conforms(data) && !accept {
		return core.DocumentJSON{}, core.ConsumeInfo{}, errMock
	}
	info := core.ConsumeInfo{MediaType: mediaType, Version: requireVersion}
	if m.on("consumer-wrong-media-type-info") {
		info.MediaType = MediaTypeJSON
	}
	var model core.DocumentJSON
	for _, mem := range doc.Members {
		switch {
		case mem.Name == "@context" && !m.on("consumer-no-representation-entries"):
			info.RepresentationEntries.Members = append(info.RepresentationEntries.Members, mem)
		case m.on("consumer-drops-entries") && (strings.HasPrefix(mem.Name, "ext") || mem.Name == "authentication"):
		default:
			model.Members = append(model.Members, mem)
		}
	}
	return model, info, nil
}

func (m *mock) Produce(doc core.DocumentJSON, _ string) ([]byte, string, error) {
	data, err := doc.MarshalJSON()
	if err != nil {
		return nil, "", err
	}
	if m.on("producer-rejects-all") || (!m.conforms(data) && !m.on("producer-accepts-all")) {
		return nil, "", errMock
	}
	_, hasCtx := doc.Get("@context")
	var out core.DocumentJSON
	for _, mem := range doc.Members {
		switch {
		case m.on("producer-drops-entries") && (strings.HasPrefix(mem.Name, "ext") || mem.Name == "authentication"):
		case m.on("producer-drops-context") && mem.Name == "@context":
		case m.on("producer-reorders-context") && mem.Name == "@context" && mem.Value.Kind == core.KindArray:
			items := append([]core.Value{}, mem.Value.Array...)
			items[0], items[len(items)-1] = items[len(items)-1], items[0]
			out.Members = append(out.Members, core.M(mem.Name, core.Array(items...)))
		default:
			out.Members = append(out.Members, mem)
		}
	}
	data, _ = out.MarshalJSON()
	if m.on("producer-non-object") {
		data = []byte("[" + string(data) + "]")
	}
	mt := MediaTypeJSON
	if hasCtx || m.on("producer-wrong-media-type") {
		mt = MediaTypeJSONLD
	}
	if m.on("producer-odd-media-type") {
		mt = "application/json"
	}
	return data, mt, nil
}

func (m *mock) Validate(doc core.DocumentJSON, _ string) ([]core.Finding, error) {
	data, err := doc.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if m.on("validator-fails") {
		return nil, errMock
	}
	if m.on("validator-noisy") || (!m.conforms(data) && !m.on("validator-silent")) {
		return []core.Finding{{Code: "mock", Path: "", Message: "does not conform"}}, nil
	}
	return nil, nil
}
