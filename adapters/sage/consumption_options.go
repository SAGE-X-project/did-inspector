package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// InspectConsumptionOptions archives actual extra options and unchanged results
// from the pinned consumer. It does not call a subject validator as an oracle.
func (*Subject) InspectConsumptionOptions(_ context.Context, q sageresolution.ConsumptionOptionsRequest) (sageresolution.ConsumptionCapture, error) {
	if q.Document.MediaType != "application/did" || q.Require != "1.1" {
		return sageresolution.ConsumptionCapture{}, errors.New("requires explicit DID 1.1 consumption options")
	}
	calls := []sageresolution.ConsumptionCapture{}
	_, _, _ = (observedConsumer{consumer.New(), &calls}).Consume(q.Document.Data, q.Document.MediaType, representation.ConsumeOptions{Require: spec.V11, Strict: q.Strict})
	return calls[0], nil
}
