// Package inspectorprobe is an Inspector-owned component observer. Its module
// path permits ordinary Go internal-package imports. It is not a production
// SAGE caller and never copies, replaces or modifies the pinned subject source.
package inspectorprobe

import "github.com/sage-x-project/did-go/internal/multiformats"

func Encode(code uint64, digest []byte) ([]byte, error) {
	return multiformats.EncodeMultihash(code, digest)
}
func Decode(encoded []byte) (uint64, []byte, error) { return multiformats.DecodeMultihash(encoded) }
