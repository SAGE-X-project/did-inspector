package sage

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
)

type sourceEnvironment struct {
	Cache    string `json:"GOMODCACHE"`
	Compiler string `json:"GOVERSION"`
}
type sourceObserver struct {
	build       func() (*debug.BuildInfo, bool)
	environment func(context.Context) (sourceEnvironment, error)
	read        func(string) ([]byte, error)
}

func readSourceEnvironment(ctx context.Context) (sourceEnvironment, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOMODCACHE", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	data, e := cmd.Output()
	if e != nil {
		return sourceEnvironment{}, e
	}
	var env sourceEnvironment
	e = json.Unmarshal(data, &env)
	return env, e
}

// InspectIntegerSource reads fixed source as data only. Module identity is not
// a proof that cached source bytes were compiled verbatim into this binary.
func (s *Subject) InspectIntegerSource(ctx context.Context, q sageresolution.IntegerSourceRequest) (sageresolution.IntegerSourceResult, error) {
	out := sageresolution.IntegerSourceResult{Request: q, Operation: "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture", Files: map[string][]byte{}, Diagnostics: []sageresolution.CodecResult{}}
	if q.Module != sageresolution.IntegerSourceModule || q.Version != sageresolution.IntegerSourceVersion {
		return out, errors.New("unselected source module")
	}
	observer := s.sourceObserver
	if observer == nil {
		observer = &sourceObserver{debug.ReadBuildInfo, readSourceEnvironment, os.ReadFile}
	}
	bi, ok := observer.build()
	if !ok || bi == nil {
		return out, errors.New("missing source build identity")
	}
	out.Compiler = bi.GoVersion
	for _, m := range bi.Deps {
		if m.Path == q.Module {
			out.Module, out.Version, out.Sum, out.Replaced = m.Path, m.Version, m.Sum, m.Replace != nil
		}
	}
	if out.Module == "" {
		return out, errors.New("missing root source dependency")
	}
	env, e := observer.environment(ctx)
	if e != nil {
		return out, e
	}
	out.EnvironmentCompiler = env.Compiler
	if !filepath.IsAbs(env.Cache) {
		return out, errors.New("source cache must be absolute")
	}
	out.Archive, e = observer.read(filepath.Join(env.Cache, "cache/download", q.Module, "@v", q.Version+".zip"))
	if e != nil {
		return out, e
	}
	z, e := zip.NewReader(bytes.NewReader(out.Archive), int64(len(out.Archive)))
	if e != nil {
		return out, e
	}
	prefix := q.Module + "@" + q.Version + "/"
	for _, f := range z.File {
		if !strings.HasPrefix(f.Name, prefix) {
			return out, errors.New("unexpected source ZIP path")
		}
		name := strings.TrimPrefix(f.Name, prefix)
		for _, dir := range q.Packages {
			if path.Dir(name) == dir && path.Clean(name) == name && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
				out.Files[name], e = observer.read(filepath.Join(env.Cache, q.Module+"@"+q.Version, filepath.FromSlash(name)))
				if e != nil {
					return out, e
				}
			}
		}
	}
	for _, request := range q.Diagnostics {
		v, e := s.InspectCodec(ctx, request)
		out.Diagnostics = append(out.Diagnostics, v)
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
