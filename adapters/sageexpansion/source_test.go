package sageexpansion

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func sourceRequest() sageresolution.IntegerSourceRequest {
	return sageresolution.IntegerSourceRequest{Module: ModulePath, Version: Version, Packages: []string{"resolver", "method", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"}}
}

func TestCaptureSourceGuards(t *testing.T) {
	q := sourceRequest()
	for _, mode := range []string{"request", "environment", "cache", "compiler", "read-zip", "invalid-zip", "read-cache"} {
		t.Run(mode, func(t *testing.T) {
			local := q
			env := environment
			read := os.ReadFile
			switch mode {
			case "request":
				local.Version = "other"
			case "environment":
				env = func(context.Context) (sourceEnvironment, error) {
					return sourceEnvironment{}, errors.New("missing env")
				}
			case "cache":
				env = func(context.Context) (sourceEnvironment, error) {
					return sourceEnvironment{Cache: "relative", Compiler: "go1.26.8"}, nil
				}
			case "compiler":
				env = func(context.Context) (sourceEnvironment, error) {
					return sourceEnvironment{Cache: "/tmp", Compiler: "other"}, nil
				}
			case "read-zip":
				read = func(string) ([]byte, error) { return nil, errors.New("missing archive") }
			case "invalid-zip":
				read = func(string) ([]byte, error) { return []byte("not zip"), nil }
			case "read-cache":
				read = func(path string) ([]byte, error) {
					if !strings.Contains(path, "/cache/download/") {
						return nil, errors.New("missing source")
					}
					return os.ReadFile(path)
				}
			}
			if _, e := captureSource(t.Context(), local, env, read); e == nil {
				t.Fatal("invalid source boundary accepted")
			}
		})
	}
	if _, e := (&Subject{}).InspectIntegerSource(t.Context(), q); e != nil {
		t.Fatal("actual pinned cache", e)
	}
	t.Setenv("PATH", "")
	if _, e := environment(t.Context()); e == nil {
		t.Fatal("missing Go executable accepted")
	}
}
