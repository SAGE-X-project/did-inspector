package did11

import (
	"context"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

func rvmError(name string) core.RetrievalResult {
	return core.RetrievalResult{Error: &core.ProcessingError{Type: nsSec + name, Title: name}}
}

// RetrieveVerificationMethod follows CID 1.0 §3.3 over the fixture
// registry, unless a fault bends it.
func (m *mock) RetrieveVerificationMethod(_ context.Context, vmIdentifier, relationship string, _ map[string]any) (core.RetrievalResult, error) {
	switch {
	case m.on("rvm-fails"):
		return core.RetrievalResult{}, errMock
	case m.on("rvm-raise-all"):
		return rvmError("INVALID_VERIFICATION_METHOD"), nil
	case m.on("rvm-never-raise"):
		stub := core.NewDocument(core.M("id", core.String(vmIdentifier)))
		return core.RetrievalResult{VerificationMethod: &stub}, nil
	}
	u, err := checks.ParseDIDURL(vmIdentifier)
	if err != nil || !u.HasFragment {
		return rvmError("INVALID_VERIFICATION_METHOD_URL"), nil
	}
	docURL, _, _ := strings.Cut(vmIdentifier, "#")
	rec, err := m.reg.Read(fixtures.Request{DID: docURL})
	if err != nil {
		return rvmError("INVALID_CONTROLLED_IDENTIFIER_DOCUMENT"), nil
	}
	doc, err := core.ParseDocumentJSON(rec.Bytes)
	if err != nil || duplicateServiceIDs(doc) {
		return rvmError("INVALID_CONTROLLED_IDENTIFIER_DOCUMENT"), nil
	}
	if id, _ := doc.Get("id"); id.Str != docURL {
		return rvmError("INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID"), nil
	}
	vm, found := findFragment(doc.Value(), docURL, u.Fragment)
	if !found || !isMethod(vm) {
		return rvmError("INVALID_VERIFICATION_METHOD"), nil
	}
	id, _ := vm.Get("id")
	if abs(docURL, id.Str) != vmIdentifier {
		return rvmError("INVALID_VERIFICATION_METHOD"), nil
	}
	if ctl, _ := vm.Get("controller"); abs(docURL, ctl.Str) != docURL && !m.on("rvm-skip-controller") {
		return rvmError("INVALID_VERIFICATION_METHOD"), nil
	}
	if !associated(doc, relationship, docURL, vmIdentifier) && !m.on("rvm-skip-relationship") {
		return rvmError("INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD"), nil
	}
	out, _ := core.DocumentFromValue(vm)
	return core.RetrievalResult{VerificationMethod: &out}, nil
}

func abs(docURL, ref string) string {
	out, err := checks.ResolveDIDReference(docURL, ref)
	if err != nil {
		return ref
	}
	return out
}

func duplicateServiceIDs(doc core.DocumentJSON) bool {
	seen := map[string]bool{}
	svc, _ := doc.Get("service")
	for _, s := range svc.Array {
		id, _ := s.Get("id")
		if seen[id.Str] {
			return true
		}
		seen[id.Str] = true
	}
	return false
}

// findFragment is CID 1.0 §3.4: the first map, in document order, whose id
// is the document URL with the fragment, or the fragment identifier.
func findFragment(v core.Value, docURL, fragment string) (core.Value, bool) {
	switch v.Kind {
	case core.KindObject:
		if id, ok := v.Get("id"); ok && (id.Str == docURL+"#"+fragment || id.Str == "#"+fragment || id.Str == fragment) {
			return v, true
		}
		for _, m := range v.Object {
			if got, ok := findFragment(m.Value, docURL, fragment); ok {
				return got, true
			}
		}
	case core.KindArray:
		for _, item := range v.Array {
			if got, ok := findFragment(item, docURL, fragment); ok {
				return got, true
			}
		}
	}
	return core.Value{}, false
}

func isMethod(v core.Value) bool {
	for _, name := range []string{"id", "type", "controller"} {
		if s, ok := v.Get(name); !ok || s.Kind != core.KindString {
			return false
		}
	}
	return true
}

func associated(doc core.DocumentJSON, relationship, docURL, vmIdentifier string) bool {
	rel, _ := doc.Get(relationship)
	for _, item := range rel.Array {
		ref := item.Str
		if item.Kind == core.KindObject {
			id, _ := item.Get("id")
			ref = id.Str
		}
		if abs(docURL, ref) == vmIdentifier {
			return true
		}
	}
	return false
}

// vmAnswerKey maps the compact JSON of every verification method vector
// to whether its judged property conforms.
func vmAnswerKey() map[string]vmAnswer {
	key := map[string]vmAnswer{}
	for _, g := range secretKeyGroups() {
		for _, v := range g.Vectors {
			data, _ := v.Method.MarshalJSON()
			key[string(data)] = vmAnswer{valid: v.Valid, property: v.Property}
		}
	}
	return key
}

type vmAnswer struct {
	valid    bool
	property string
}

// ValidateVerificationMethod reports a finding at the judged property of
// every vector the answer key calls non-conforming.
func (m *mock) ValidateVerificationMethod(vm core.DocumentJSON, _ string) ([]core.Finding, error) {
	if m.on("vm-validator-fails") {
		return nil, errMock
	}
	data, err := vm.MarshalJSON()
	if err != nil {
		return nil, err
	}
	a, known := m.vmKey[string(data)]
	switch {
	case m.on("vm-validator-noisy"):
		return []core.Finding{{Code: "mock", Path: "", Message: "does not conform"}}, nil
	case m.on("vm-validator-silent"), !known, a.valid:
		return nil, nil
	}
	return []core.Finding{{Code: "mock", Path: "/" + a.property, Message: "does not conform"}}, nil
}
