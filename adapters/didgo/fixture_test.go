package didgo

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/fixtures"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
)

func mustDID(t *testing.T, s string) did.DID {
	t.Helper()
	d, err := did.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestFixtureMethodRead checks that the driver maps every outcome of
// fixtures.Registry.Read to did-go's driver contract.
func TestFixtureMethodRead(t *testing.T) {
	m := newFixtureMethod(registry(t))
	ctx := context.Background()
	if m.Name() != fixtures.Method || !slices.Equal(m.Produces(), []string{"application/did", "application/did+json"}) {
		t.Errorf("Name %q Produces %v", m.Name(), m.Produces())
	}

	rr, err := m.Read(ctx, mustDID(t, "did:example:a"), method.ReadOptions{})
	if err != nil || rr.Metadata.VersionID != "2" || rr.ContentType != "application/did" || len(rr.Data) == 0 || rr.Metadata.Deactivated {
		t.Fatalf("current version: %+v %v", rr, err)
	}
	rr, err = m.Read(ctx, mustDID(t, "did:example:a"), method.ReadOptions{VersionID: "1"})
	if err != nil || rr.Metadata.VersionID != "1" {
		t.Errorf("versionId: %+v %v", rr, err)
	}
	at := time.Date(2021, 1, 15, 0, 0, 0, 0, time.UTC)
	rr, err = m.Read(ctx, mustDID(t, "did:example:a"), method.ReadOptions{VersionTime: &at})
	if err != nil || rr.Metadata.VersionID != "1" {
		t.Errorf("versionTime: %+v %v", rr, err)
	}
	rr, err = m.Read(ctx, mustDID(t, "did:example:gone"), method.ReadOptions{})
	if err != nil || !rr.Metadata.Deactivated {
		t.Errorf("deactivated: %+v %v", rr, err)
	}

	cases := []struct {
		did  string
		opts method.ReadOptions
		want error
	}{
		{"did:example:nothing", method.ReadOptions{}, method.ErrNotFound},
		{"did:example:a", method.ReadOptions{VersionID: "9"}, method.ErrNotFound},
		{"did:other:a", method.ReadOptions{}, method.ErrNotSupported},
	}
	for _, c := range cases {
		if _, err := m.Read(ctx, mustDID(t, c.did), c.opts); !errors.Is(err, c.want) {
			t.Errorf("%s %+v: %v, want %v", c.did, c.opts, err, c.want)
		}
	}
	for _, d := range []string{"did:example:broken", "did:example:badmeta"} {
		_, err := m.Read(ctx, mustDID(t, d), method.ReadOptions{})
		if err == nil || errors.Is(err, method.ErrNotFound) || errors.Is(err, method.ErrNotSupported) {
			t.Errorf("%s: %v, want a plain driver failure", d, err)
		}
	}
	var inj *fixtures.InjectedError
	if _, err := m.Read(ctx, mustDID(t, "did:example:broken"), method.ReadOptions{}); !errors.As(err, &inj) {
		t.Errorf("injected failure lost: %v", err)
	}
}

func TestFixtureMethodOtherOperations(t *testing.T) {
	m := newFixtureMethod(registry(t))
	ctx := context.Background()
	d := mustDID(t, "did:example:a")
	if _, err := m.Create(ctx, nil, method.CreateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error("Create supported")
	}
	if _, err := m.Update(ctx, d, nil, method.UpdateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error("Update supported")
	}
	if _, err := m.Deactivate(ctx, d, method.DeactivateOptions{}); !errors.Is(err, method.ErrNotSupported) {
		t.Error("Deactivate supported")
	}
}

func TestLoadFixtureRegistry(t *testing.T) {
	s := New()
	ctx := context.Background()
	res, err := s.Resolve(ctx, "did:example:a", nil)
	if err != nil || errorType(res.ResolutionMetadata) != "https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED" {
		t.Errorf("before loading: %s %v", compact(t, res.ResolutionMetadata), err)
	}
	if err := s.LoadFixtureRegistry(nil); err == nil {
		t.Error("nil registry loaded")
	}
	if err := s.LoadFixtureRegistry(&fixtures.Registry{Format: "x"}); err == nil {
		t.Error("invalid registry loaded")
	}
	if err := s.LoadFixtureRegistry(registry(t)); err != nil {
		t.Fatal(err)
	}
	res, err = s.Resolve(ctx, "did:example:a", nil)
	if err != nil || res.Document == nil {
		t.Errorf("after loading: %s %v", compact(t, res.ResolutionMetadata), err)
	}
	// A later call replaces the registry.
	empty := &fixtures.Registry{Format: fixtures.Format, Method: fixtures.Method, Entries: map[string]fixtures.Entry{}}
	if err := s.LoadFixtureRegistry(empty); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Resolve(ctx, "did:example:a", nil)
	if errorType(res.ResolutionMetadata) != "https://www.w3.org/ns/did#NOT_FOUND" {
		t.Errorf("after replacing: %s", compact(t, res.ResolutionMetadata))
	}
}
