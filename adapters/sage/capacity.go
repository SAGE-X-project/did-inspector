package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/inspectorprobe"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"runtime/debug"
)

func (s *Subject) InspectCapacity(ctx context.Context, q sageresolution.CapacityRequest) (sageresolution.CapacityResult, error) {
	v := sageresolution.CapacityResult{Request: q, Role: sageresolution.MultihashRole}
	if ctx.Err() != nil {
		return v, ctx.Err()
	}
	if q.Operation != "encode" && q.Operation != "decode" {
		return v, errors.New("unknown capacity component operation")
	}
	if q.Header != 'u' || len(q.Data) > 4096 || len(q.Encoded) > 4096 {
		return v, errors.New("requires bounded u/64 component input")
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
