package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/inspectorprobe"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"runtime/debug"
)

// componentObserverIdentity records the Inspector-owned local module separately
// from the unreplaced subject dependency captured by InspectIntegerSource.
func componentObserverIdentity(read func() (*debug.BuildInfo, bool)) (sageresolution.ComponentObserver, error) {
	out := sageresolution.ComponentObserver{}
	bi, ok := read()
	if !ok || bi == nil {
		return out, errors.New("missing component observer build identity")
	}
	out.Compiler = bi.GoVersion
	for _, m := range bi.Deps {
		if m.Path == sageresolution.ComponentObserverModule && m.Replace != nil {
			out.Module = m.Path
			out.Version = m.Version
			out.Replacement = m.Replace.Path
			out.ReplacementVersion = m.Replace.Version
			out.ReplacementSum = m.Replace.Sum
		}
	}
	normalized := out
	if normalized.ReplacementVersion == "" {
		normalized.ReplacementVersion = "(devel)"
	}
	if normalized != (sageresolution.ComponentObserver{Module: sageresolution.ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", ReplacementVersion: "(devel)", Compiler: "go1.26.8"}) {
		return out, errors.New("unselected component observer module")
	}
	return out, nil
}
func (s *Subject) InspectMultihash(ctx context.Context, q sageresolution.MultihashRequest) (sageresolution.MultihashResult, error) {
	out := sageresolution.MultihashResult{Request: q, Role: sageresolution.MultihashRole}
	var err error
	if ctx.Err() != nil {
		return out, ctx.Err()
	}

	if q.Operation != "encode" && q.Operation != "decode" {
		return out, errors.New("unknown component observation operation")
	}
	read := debug.ReadBuildInfo
	if s.sourceObserver != nil {
		read = s.sourceObserver.build
	}
	out.Observer, err = componentObserverIdentity(read)
	if err != nil {
		return out, err
	}
	switch q.Operation {
	case "encode":
		out.Operation = sageresolution.IntegerSourceModule + "/internal/multiformats.EncodeMultihash"
		out.Encoded, err = inspectorprobe.Encode(q.Code, q.Digest)
	case "decode":
		out.Operation = sageresolution.IntegerSourceModule + "/internal/multiformats.DecodeMultihash"
		out.Code, out.Digest, err = inspectorprobe.Decode(q.Encoded)
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out, nil
}
