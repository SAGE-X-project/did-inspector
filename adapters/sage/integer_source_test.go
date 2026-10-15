package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func sourceTest(t *testing.T) (*Subject, sageresolution.IntegerSourceRequest) {
	t.Helper()
	archive, e := os.ReadFile("../../checks/sourcearith/testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, sum, e := sourcearith.ArchiveFiles(archive, sageresolution.IntegerSourceModule+"@"+sageresolution.IntegerSourceVersion)
	if e != nil || sum != sageresolution.IntegerSourceSum {
		t.Fatal(e, sum)
	}
	q := sageresolution.IntegerSourceRequest{Module: sageresolution.IntegerSourceModule, Version: sageresolution.IntegerSourceVersion, Packages: []string{"vm", "did", "internal/multiformats"}, Diagnostics: []sageresolution.CodecRequest{{Name: "Ed25519", Key: make([]byte, 32), Encoded: "z0"}}}
	s := &Subject{sourceObserver: &sourceObserver{build: func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{GoVersion: "go1.26.8", Deps: []*debug.Module{{Path: q.Module, Version: q.Version, Sum: sum}, {Path: sageresolution.ComponentObserverModule, Version: "v0.0.0", Replace: &debug.Module{Path: "../sageprobe"}}}}, true
	}, environment: func(context.Context) (sourceEnvironment, error) {
		return sourceEnvironment{Cache: "/fixture", Compiler: "go1.26.8"}, nil
	}, read: func(name string) ([]byte, error) {
		if filepath.Ext(name) == ".zip" {
			return archive, nil
		}
		prefix := filepath.Join("/fixture", q.Module+"@"+q.Version) + string(filepath.Separator)
		if len(name) >= len(prefix) {
			if b, ok := files[filepath.ToSlash(name[len(prefix):])]; ok {
				return b, nil
			}
		}
		return nil, errors.New("unobserved file")
	}}}
	return s, q
}
func TestFixtureSourceCaptureKeepsOriginAndDiagnostics(t *testing.T) {
	s, q := sourceTest(t)
	v, e := s.InspectIntegerSource(t.Context(), q)
	if e != nil || len(v.Files) != 16 || v.Sum != sageresolution.IntegerSourceSum || v.Replaced || len(v.Diagnostics) != 1 || v.Diagnostics[0].Operation != "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey" {
		t.Fatal("capture", e)
	}
	files, sum, e := sourcearith.ArchiveFiles(v.Archive, q.Module+"@"+q.Version)
	if e != nil || sum != v.Sum || len(sourcearith.SourceFiles(files, q.Packages)) != len(v.Files) {
		t.Fatal(e)
	}
}
func TestSourceCaptureFailures(t *testing.T) {
	for _, mutate := range []func(*Subject, *sageresolution.IntegerSourceRequest){func(s *Subject, q *sageresolution.IntegerSourceRequest) { q.Module = "other" }, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.build = func() (*debug.BuildInfo, bool) { return nil, false }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.build = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{}, true }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.environment = func(context.Context) (sourceEnvironment, error) { return sourceEnvironment{}, errors.New("missing Go") }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.environment = func(context.Context) (sourceEnvironment, error) { return sourceEnvironment{Cache: "relative"}, nil }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.read = func(string) ([]byte, error) { return nil, errors.New("missing cache") }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		s.sourceObserver.read = func(string) ([]byte, error) { return []byte("invalid ZIP"), nil }
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) {
		old := s.sourceObserver.read
		s.sourceObserver.read = func(p string) ([]byte, error) {
			if filepath.Ext(p) == ".zip" {
				return old(p)
			}
			return nil, errors.New("missing source")
		}
	}, func(s *Subject, q *sageresolution.IntegerSourceRequest) { q.Diagnostics[0].Name = "unknown" }} {
		s, q := sourceTest(t)
		mutate(s, &q)
		if _, e := s.InspectIntegerSource(t.Context(), q); e == nil {
			t.Fatal("capture failure ignored")
		}
	}
	if _, e := (&Subject{}).InspectIntegerSource(t.Context(), sageresolution.IntegerSourceRequest{Module: sageresolution.IntegerSourceModule, Version: sageresolution.IntegerSourceVersion}); e == nil {
		t.Log("actual test binary contains pinned build identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := readSourceEnvironment(ctx); e == nil {
		t.Fatal("cancelled Go env")
	}
	env, e := readSourceEnvironment(t.Context())
	if e != nil || env.Compiler != "go1.26.8" || !filepath.IsAbs(env.Cache) {
		t.Fatal(env, e)
	}
}
