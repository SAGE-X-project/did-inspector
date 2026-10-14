package sageresolution

import "context"
import "github.com/sage-x-project/did-inspector/core"

const IntegerSourceModule = "github.com/sage-x-project/did-go"
const IntegerSourceVersion = "v0.0.0-20261012015322-ed54c505eafe"
const IntegerSourceSum = "h1:phZzJEVaBYD9ylcNhmODNZ4mSp3N4j/4HwILUmFWnrE="

type IntegerSourceRequest struct {
	Module      string         `json:"module"`
	Version     string         `json:"version"`
	Packages    []string       `json:"packages"`
	Diagnostics []CodecRequest `json:"diagnostics"`
}
type IntegerSourceResult struct {
	Request             IntegerSourceRequest `json:"request"`
	Operation           string               `json:"operation"`
	Module              string               `json:"module"`
	Version             string               `json:"version"`
	Sum                 string               `json:"sum"`
	Replaced            bool                 `json:"replaced"`
	Compiler            string               `json:"compiler"`
	EnvironmentCompiler string               `json:"environment_compiler"`
	Archive             []byte               `json:"archive"`
	Files               map[string][]byte    `json:"files"`
	Diagnostics         []CodecResult        `json:"diagnostics"`
}
type IntegerSourceSubject interface {
	core.Subject
	InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error)
}
