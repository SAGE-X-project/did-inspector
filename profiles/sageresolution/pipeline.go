package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

var pipelineStatements = []string{
	"did11-cr20260305#production-and-consumption.10",
	"did11-cr20260305#production-and-consumption.11",
	"did11-cr20260305#production-and-consumption.16",
	"did11-cr20260305#production-and-consumption.17",
	"did11-cr20260305#consumption.2",
}

const pipelineProducer = "github.com/sage-x-project/did-go/producer.Producer.Produce"
const pipelineConsumer = "github.com/sage-x-project/did-go/consumer.Consumer.Consume"

func pipelineMedia(media string) bool {
	value, _, err := mime.ParseMediaType(media)
	return ascii(media) && err == nil && value == "application/did"
}
func combinedMaps(model, entries core.Value) (core.Value, bool) {
	members := append(append([]core.Member{}, model.Object...), entries.Object...)
	value := core.Object(members...)
	return value, len(checks.DuplicateMembers(value)) == 0
}
func pipelineEqual(a, b core.Value) core.Verdict {
	if !boundedInfraValue(a) || !boundedInfraValue(b) {
		return core.NotSupported
	}
	eq, _ := checks.EqualJSON(a, b)
	if !eq {
		return core.Fail
	}
	return core.Pass
}
func judgePipeline(result PipelineResult, input string) []core.Observation {
	raw, archiveError := json.Marshal(result)
	unavailable := func(detail string) []core.Observation {
		out := make([]core.Observation, 0, len(pipelineStatements))
		for _, id := range pipelineStatements {
			out = append(out, core.Observation{Statement: id, Verdict: core.Error, Input: input, Observed: string(raw), Detail: detail})
		}
		return out
	}
	if archiveError != nil {
		// Preserve malformed RawMessage fields as byte strings in an error archive.
		safe := result
		safe.Result.Metadata, safe.Result.ContentMetadata, safe.Result.Snapshot = nil, nil, nil
		raw, _ = json.Marshal(struct {
			Capture         PipelineResult `json:"capture"`
			Metadata        []byte         `json:"metadata_bytes"`
			ContentMetadata []byte         `json:"content_metadata_bytes"`
			Snapshot        []byte         `json:"snapshot_bytes"`
			Error           string         `json:"archive_error"`
		}{safe, result.Result.Metadata, result.Result.ContentMetadata, result.Result.Snapshot, archiveError.Error()})
		return unavailable("native result archive failed; original JSON field bytes retained")
	}
	if len(result.Producer) != 1 || len(result.Consumer) != 1 {
		return unavailable("one actual producer and consumer call required")
	}
	p, c := result.Producer[0], result.Consumer[0]
	if p.Operation != pipelineProducer || c.Operation != pipelineConsumer || p.Version != "1.1" || !p.JSONLD || p.IncludeSecret || c.Version != "1.1" || !c.JSONLD || c.Require != "unknown" || c.Expected != "unknown" || c.Strict {
		return unavailable("missing or mismatched actual native 1.1 call attribution/options")
	}
	if p.Error != "" || c.Error != "" || p.CaptureError != "" || c.CaptureError != "" {
		return unavailable("actual delegated or accessor capture error retained")
	}
	r := result.Result
	md, err := parse(r.Metadata)
	if err != nil {
		return unavailable("unusable native metadata")
	}
	if _, ok := md.Get("error"); ok {
		return unavailable("native resolver returned an error")
	}
	if !r.HasContent || r.ContentKind != "document" || r.Exchange != nil || r.Native != nil || !bytes.Equal(p.Output, c.Input) || !bytes.Equal(p.Output, r.Raw) {
		return unavailable("unmatched producer, consumer and resolver byte boundaries")
	}
	maps := make([]core.Value, 0, 5)
	for _, data := range [][]byte{p.Model, p.Entries, p.Output, c.Model, c.Entries} {
		value, err := parse(data)
		if err != nil {
			return unavailable("unusable actual boundary map: " + err.Error())
		}
		maps = append(maps, value.Value())
	}
	produced, uniqueP := combinedMaps(maps[0], maps[1])
	consumed, uniqueC := combinedMaps(maps[3], maps[4])
	if !uniqueP || !uniqueC {
		return unavailable("overlapping data and representation-specific entry names")
	}
	// @context has explicit JSON-LD production rules: the producer may add
	// the base context even when the input representation map is empty.
	withoutContext := func(value core.Value) core.Value {
		members := []core.Member{}
		for _, m := range value.Object {
			if m.Name != "@context" {
				members = append(members, m)
			}
		}
		return core.Object(members...)
	}
	producerVerdict := pipelineEqual(withoutContext(produced), withoutContext(maps[2]))
	mediaVerdict := core.Pass
	if !pipelineMedia(p.MediaType) {
		mediaVerdict = core.Fail
	}
	context, exists := maps[2].Get("@context")
	if !exists || !representationContext(context) {
		return unavailable("selected JSON-LD input with DID 1.1 context required")
	}
	representationVerdict := pipelineEqual(core.Object(core.M("@context", context)), maps[4])
	if _, leaked := maps[3].Get("@context"); leaked {
		representationVerdict = core.Fail
	}
	wantModel := []core.Member{}
	for _, m := range maps[2].Object {
		if m.Name != "@context" {
			wantModel = append(wantModel, m)
		}
	}
	consumerVerdict := pipelineEqual(core.Object(wantModel...), maps[3])
	if len(c.DroppedTerms) > 0 {
		consumerVerdict = core.NotSupported
	}
	wholeVerdict := pipelineEqual(maps[2], consumed)
	if len(c.DroppedTerms) > 0 {
		wholeVerdict = core.NotSupported
	}
	if !pipelineMedia(c.MediaType) {
		representationVerdict, consumerVerdict, wholeVerdict = core.NotSupported, core.NotSupported, core.NotSupported
	}
	verdicts := []core.Verdict{producerVerdict, mediaVerdict, representationVerdict, consumerVerdict, wholeVerdict}
	out := make([]core.Observation, 0, len(pipelineStatements))
	for i, id := range pipelineStatements {
		out = append(out, core.Observation{Statement: id, Verdict: verdicts[i], Input: input, Expected: "Actual native 1.1 call-boundary entries are preserved with application/did media declarations", Observed: string(raw), Detail: "Fresh passive producer/consumer capture in advanced/sage resolution. Actual pre-producer data/representation maps, delegated bytes and returned separate consumer maps are compared independently in the selected ASCII/safe-integer JSON range. Only @context has explicit representation processing here. Dropped-term processing, arbitrary typed values, all representations, full JSON-LD semantics, remote contexts, internal conversions, authority and whole conformance remain unestablished. No post-consumption getter, prior verdict or subject validator supplies the producer oracle."})
	}
	return out
}
func appendPipelineCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-pipeline-record-%d", p.Name, i), Profile: p.Name, Statements: append([]string{}, pipelineStatements...), Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			missing := func(v core.Verdict, detail string) []core.Observation {
				out := unavailable(pipelineStatements, v, detail)
				for i := range out {
					out[i].Input = string(input)
				}
				return out
			}
			s, ok := target.(PipelineSubject)
			if !ok {
				return missing(core.NotSupported, "no actual native pipeline boundary operation")
			}
			result, err := s.InspectPipeline(ctx, record, q)
			if err != nil {
				return missing(core.Error, err.Error())
			}
			return judgePipeline(result, string(input))
		}})
	}
}
