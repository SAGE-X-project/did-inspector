package sage

import (
	"context"
	"github.com/sage-x-project/did-go/jsonld"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func (*Subject) InspectBaseContext(context.Context) (sageresolution.BaseContextResult, error) {
	return localBaseContext(spec.V11), nil
}
func localBaseContext(v spec.Version) sageresolution.BaseContextResult {
	u, b, e := jsonld.BaseContext(v)
	out := sageresolution.BaseContextResult{Operation: "github.com/sage-x-project/did-go/jsonld.BaseContext", Version: v.String(), URL: u, Data: append([]byte(nil), b...)}
	if e != nil {
		out.Error = e.Error()
	}
	return out
}
