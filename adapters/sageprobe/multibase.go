package inspectorprobe

import "github.com/sage-x-project/did-go/internal/multiformats"

// These calls execute the original pinned component without replacing it.
func EncodeMultibase(header byte, data []byte) (string, error) {
	return multiformats.EncodeMultibase(header, data)
}
func DecodeMultibase(s string) (byte, []byte, error) { return multiformats.DecodeMultibase(s) }
