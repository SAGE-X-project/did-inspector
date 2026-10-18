package sageresource

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

type sourceEnvironment struct {
	Cache    string `json:"GOMODCACHE"`
	Compiler string `json:"GOVERSION"`
}

func environment(ctx context.Context) (sourceEnvironment, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOMODCACHE", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	data, err := cmd.Output()
	if err != nil {
		return sourceEnvironment{}, err
	}
	var v sourceEnvironment
	err = json.Unmarshal(data, &v)
	return v, err
}

func (*Subject) InspectIntegerSource(ctx context.Context, q sageresolution.IntegerSourceRequest) (sageresolution.IntegerSourceResult, error) {
	return captureSource(ctx, q, environment, os.ReadFile)
}

func captureSource(ctx context.Context, q sageresolution.IntegerSourceRequest, env func(context.Context) (sourceEnvironment, error), read func(string) ([]byte, error)) (sageresolution.IntegerSourceResult, error) {
	out := sageresolution.IntegerSourceResult{Request: q, Module: ModulePath, Version: Version, Sum: Sum, Compiler: runtime.Version(), Operation: "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture", Files: map[string][]byte{}, Diagnostics: []sageresolution.CodecResult{}}
	packages := []string{"dereferencer", "relyingparty", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"}
	if q.Module != ModulePath || q.Version != Version || !reflect.DeepEqual(q.Packages, packages) || len(q.Diagnostics) != 0 {
		return out, errors.New("requires fixed resource source request")
	}
	v, err := env(ctx)
	if err != nil {
		return out, err
	}
	out.EnvironmentCompiler = v.Compiler
	if !filepath.IsAbs(v.Cache) || v.Compiler != out.Compiler {
		return out, errors.New("source cache or compiler mismatch")
	}
	out.Archive, err = read(filepath.Join(v.Cache, "cache/download", ModulePath, "@v", Version+".zip"))
	if err != nil {
		return out, err
	}
	files, sum, err := sourcearith.ArchiveFiles(out.Archive, ModulePath+"@"+Version)
	if err != nil || sum != Sum {
		return out, errors.New("unbound source ZIP")
	}
	for name := range sourcearith.SourceFiles(files, packages) {
		out.Files[name], err = read(filepath.Join(v.Cache, ModulePath+"@"+Version, filepath.FromSlash(name)))
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
