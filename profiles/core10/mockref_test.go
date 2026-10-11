package core10

import (
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// ResolveDIDURLReference resolves with the inspector's own RFC 3986
// implementation, unless a fault bends it.
func (m *mock) ResolveDIDURLReference(base, ref string) (string, error) {
	switch {
	case m.on("reference-refused"):
		return "", errMock
	case m.on("reference-appended"):
		return base + ref, nil
	}
	return checks.ResolveDIDReference(base, ref)
}

// ProduceRepresentation produces the requested representation: the JSON-LD
// one under its media type, the JSON one otherwise.
func (m *mock) ProduceRepresentation(doc core.DocumentJSON, _, mediaType string) ([]byte, string, error) {
	if m.on("representation-refused") {
		return nil, "", errMock
	}
	data, err := doc.MarshalJSON()
	if err != nil {
		return nil, "", err
	}
	mt := MediaTypeJSON
	if checks.MediaTypeEssence(mediaType) == MediaTypeJSONLD && !m.on("representation-json-ld-as-json") {
		mt = MediaTypeJSONLD
	}
	return data, mt, nil
}
