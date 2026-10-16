package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/inspectorprobe"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"runtime/debug"
)

func (s *Subject) InspectMultibaseExtension(ctx context.Context, q sageresolution.CapacityRequest) (sageresolution.CapacityResult, error) {
	v := sageresolution.CapacityResult{Request: q, Role: sageresolution.MultihashRole}
	if ctx.Err() != nil {
		return v, ctx.Err()
	}
	if (q.Operation != "encode" && q.Operation != "decode") || len(q.Data) > 64 || len(q.Encoded) > 256 {
		return v, errors.New("requires bounded explicit multibase extension input")
	}
	header := q.Header
	if q.Operation == "decode" && len(q.Encoded) > 0 {
		header = q.Encoded[0]
	}
	if header != 'z' && header != 'u' && header != 'f' {
		return v, errors.New("unselected extension header")
	}
	read := debug.ReadBuildInfo
	if s.sourceObserver != nil {
		read = s.sourceObserver.build
	}
	var err error
	v.Observer, err = componentObserverIdentity(read)
	if err != nil {
		return v, err
	}
	if q.Operation == "encode" {
		v.Operation = sageresolution.IntegerSourceModule + "/internal/multiformats.EncodeMultibase"
		v.Encoded, err = inspectorprobe.EncodeMultibase(q.Header, q.Data)
	} else {
		v.Operation = sageresolution.IntegerSourceModule + "/internal/multiformats.DecodeMultibase"
		v.Header, v.Data, err = inspectorprobe.DecodeMultibase(q.Encoded)
	}
	if err != nil {
		v.Error = err.Error()
	}
	return v, nil
}
