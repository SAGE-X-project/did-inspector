package sageresolution

import "context"
import "github.com/sage-x-project/did-inspector/core"

// KeyConversionRequest contains published public key bytes only.
type KeyConversionRequest struct {
	Name string `json:"name"`
	Key  []byte `json:"key"`
}

// KeyConversionResult records actual values before and after conversion through
// a standard library public key. It carries no subject validation verdict.
type KeyConversionResult struct {
	Request      KeyConversionRequest `json:"request"`
	Operation    string               `json:"operation"`
	CryptoType   string               `json:"crypto_type,omitempty"`
	Before       string               `json:"before"`
	After        string               `json:"after"`
	BeforeRaw    []byte               `json:"before_raw"`
	AfterRaw     []byte               `json:"after_raw"`
	BeforeType   string               `json:"before_type"`
	AfterType    string               `json:"after_type"`
	BuildError   string               `json:"build_error,omitempty"`
	BeforeError  string               `json:"before_error,omitempty"`
	ConvertError string               `json:"convert_error,omitempty"`
	AfterError   string               `json:"after_error,omitempty"`
}
type KeyConversionSubject interface {
	core.Subject
	InspectKeyConversion(context.Context, KeyConversionRequest) (KeyConversionResult, error)
}
