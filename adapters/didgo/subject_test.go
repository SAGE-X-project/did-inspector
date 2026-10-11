package didgo

import (
	"runtime/debug"
	"slices"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/core10"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

func TestSupports(t *testing.T) {
	s := New()
	for _, c := range core.Capabilities() {
		if !core.Implements(s, c) {
			t.Errorf("subject does not implement %s", c)
		}
	}
	want := map[string][]core.Capability{
		core10.Name: {core.CapDIDParser, core.CapDocumentProducer, core.CapDocumentConsumer, core.CapDocumentValidator, core.CapV10Functions, core.CapFixtureMethod},
		did11.Name:  {core.CapDIDParser, core.CapDocumentProducer, core.CapDocumentConsumer, core.CapDocumentValidator, core.CapResolver, core.CapDereferencer, core.CapFixtureMethod},
		"did-9.9":   nil,
	}
	for p, caps := range want {
		if got := Capabilities(p); !slices.Equal(got, caps) {
			t.Errorf("Capabilities(%s) = %v, want %v", p, got, caps)
		}
	}
	if s.Supports(core10.Name, core.CapResolver) || s.Supports(did11.Name, core.CapV10Functions) {
		t.Error("a profile declares the other profile's resolution functions")
	}
}

func TestDescribe(t *testing.T) {
	pseudo := "v0.0.0-20261011184433-82160c9bc606"
	cases := []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want core.SubjectInfo
	}{
		{"no build info", nil, false, core.SubjectInfo{Name: Name, Version: "unknown", Revision: "unknown"}},
		{"not a dependency", &debug.BuildInfo{Deps: []*debug.Module{{Path: "example.com/x", Version: "v1.0.0"}}}, true,
			core.SubjectInfo{Name: Name, Version: "unknown", Revision: "unknown"}},
		{"pseudo-version", &debug.BuildInfo{Deps: []*debug.Module{{Path: ModulePath, Version: pseudo}}}, true,
			core.SubjectInfo{Name: Name, Version: pseudo, Revision: "82160c9bc606"}},
		{"replaced", &debug.BuildInfo{Deps: []*debug.Module{{Path: ModulePath, Version: pseudo, Replace: &debug.Module{Path: "../did-go"}}}}, true,
			core.SubjectInfo{Name: Name, Version: "unknown (replaced by ../did-go)", Revision: "unknown"}},
	}
	for _, c := range cases {
		got := describe(func() (*debug.BuildInfo, bool) { return c.bi, c.ok })
		if got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
	if New().Describe().Name != Name {
		t.Error("Describe does not name did-go")
	}
}

func TestRevisionOf(t *testing.T) {
	cases := map[string]string{
		"v0.0.0-20261011184433-82160c9bc606":              "82160c9bc606",
		"v1.2.4-0.20261011184433-82160c9bc606":            "82160c9bc606",
		"v1.2.3-pre.0.20261011184433-82160c9bc606":        "82160c9bc606",
		"v2.0.0-20261011184433-82160c9bc606+incompatible": "82160c9bc606",
		"v1.2.3":                    "v1.2.3",
		"v1.2.3-rc-1":               "v1.2.3-rc-1",
		"v0.0.0-2026101118443-zzzz": "v0.0.0-2026101118443-zzzz",
	}
	for in, want := range cases {
		if got := revisionOf(in); got != want {
			t.Errorf("revisionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	s := New()
	d, err := s.ParseDID("did:example:123")
	if err != nil || d != (core.DIDParts{DID: "did:example:123", Method: "example", MethodSpecificID: "123"}) {
		t.Fatalf("ParseDID = %+v, %v", d, err)
	}
	if _, err := s.ParseDID("did:example:123#x"); err == nil {
		t.Error("a DID URL parsed as a DID")
	}
	u, err := s.ParseDIDURL("did:example:123/p?q=1#f")
	want := core.DIDURLParts{DIDURL: "did:example:123/p?q=1#f", DID: core.DIDParts{DID: "did:example:123", Method: "example", MethodSpecificID: "123"},
		Path: "/p", Query: "q=1", HasQuery: true, Fragment: "f", HasFragment: true}
	if err != nil || u != want {
		t.Fatalf("ParseDIDURL = %+v, %v", u, err)
	}
	if _, err := s.ParseDIDURL("did:example:123/pa th"); err == nil {
		t.Error("a DID URL with a space parsed")
	}
}
