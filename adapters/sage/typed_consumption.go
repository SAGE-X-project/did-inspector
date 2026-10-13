package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"time"
)

// InspectTypedConsumption reads literal bytes with the unchanged selected
// consumer, then witnesses actual returned types. No producer or input-derived
// replacement model supplies this evidence.
func (s *Subject) InspectTypedConsumption(_ context.Context, q sageresolution.ConsumptionRequest) (sageresolution.TypedConsumptionResult, error) {
	out := sageresolution.TypedConsumptionResult{}
	if q.MediaType != "application/did" {
		return out, errors.New("requires DID 1.1 inspection media")
	}
	calls := []sageresolution.ConsumptionCapture{}
	d, _, _ := (observedConsumer{consumer.New(), &calls}).Consume(q.Data, q.MediaType, representation.ConsumeOptions{})
	out.Call = calls[0]
	if d == nil {
		return out, nil
	}
	out.ID, out.ControllerShape = d.ID().String(), d.ControllerShape().String()
	for _, c := range d.Controllers() {
		out.Controllers = append(out.Controllers, c.String())
	}
	var fieldsErr, entriesErr error
	out.Fields, fieldsErr = actualTypedMembers(d.Extensions())
	out.Entries, entriesErr = actualTypedMembers(d.RepresentationEntries())
	if e := errors.Join(fieldsErr, entriesErr); e != nil {
		out.CaptureError = e.Error()
		return out, nil
	}
	for _, m := range d.VerificationMethods() {
		x := sageresolution.ConsumedMethod{ID: m.ID.String()}
		if m.Expires != nil {
			x.Expires = &sageresolution.TypedValue{Kind: "datetime", Text: m.Expires.Format(time.RFC3339Nano)}
		}
		if m.Revoked != nil {
			x.Revoked = &sageresolution.TypedValue{Kind: "datetime", Text: m.Revoked.Format(time.RFC3339Nano)}
		}
		out.Methods = append(out.Methods, x)
	}
	return out, nil
}
