package kit

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
)

// DocFile is the format of testdata/documents.json: groups of DID
// documents that conform or do not conform to the data model rules their
// statements state.
type DocFile struct {
	Groups []DocGroup `json:"groups"`
}

// DocGroup becomes up to three cases, one per capability it judges.
type DocGroup struct {
	// Case is the case id suffix.
	Case    string `json:"case"`
	Note    string `json:"note"`
	Partial string `json:"partial,omitempty"`
	// Judges lists, per capability ("consumer", "producer", "validator"),
	// the statements that capability's case judges. A capability without
	// an entry gets no case.
	Judges map[string][]string `json:"judges"`
	// SkipGeneral keeps the profile's general statements (ConsumerErrors,
	// ProducerNonConforming) out of the group's cases, for groups whose
	// invalid inputs are not non-conforming documents.
	SkipGeneral bool         `json:"skipGeneral,omitempty"`
	Valid       []DocFixture `json:"valid"`
	Invalid     []DocFixture `json:"invalid"`
}

// DocFixture is one document. Text, when set, replaces the document with
// raw bytes; such fixtures are only consumed.
type DocFixture struct {
	Name      string     `json:"name"`
	Why       string     `json:"why,omitempty"`
	Document  core.Value `json:"document"`
	Text      *string    `json:"text,omitempty"`
	MediaType string     `json:"mediaType,omitempty"`
}

// Bytes returns the representation of the fixture: Text, or the compact
// JSON text of Document.
func (f DocFixture) Bytes() []byte {
	if f.Text != nil {
		return []byte(*f.Text)
	}
	data, err := f.Document.MarshalJSON()
	if err != nil {
		// Fixtures come from JSON text, so they always marshal.
		panic(err)
	}
	return data
}

// Doc returns the fixture's document as a DocumentJSON; a non-object
// document returns false.
func (f DocFixture) Doc() (core.DocumentJSON, bool) {
	if f.Text != nil {
		return core.DocumentJSON{}, false
	}
	d, err := core.DocumentFromValue(f.Document)
	return d, err == nil
}

// DocConfig is what the document cases need from a profile.
type DocConfig struct {
	Profile string
	// Version is the DID version passed as version and requireVersion.
	Version string
	// MediaType returns the media type a fixture is consumed under when it
	// names none.
	MediaType func(DocFixture) string
	// ConsumerErrors are the statements that require a consumer to produce
	// errors for non-conforming documents; consumer cases with invalid
	// fixtures judge them too.
	ConsumerErrors []string
	// ProducerNonConforming are the statements that forbid a producer to
	// produce non-conforming documents; producer cases with invalid
	// fixtures judge them too.
	ProducerNonConforming []string
}

func (c DocConfig) mediaType(f DocFixture) string {
	if f.MediaType != "" {
		return f.MediaType
	}
	return c.MediaType(f)
}

// Capability names used in DocGroup.Judges.
const (
	JudgeConsumer  = "consumer"
	JudgeProducer  = "producer"
	JudgeValidator = "validator"
)

// DocCases returns the cases of every group.
func DocCases(cfg DocConfig, f DocFile) []core.Case {
	var out []core.Case
	for _, g := range f.Groups {
		for _, kind := range []string{JudgeConsumer, JudgeProducer, JudgeValidator} {
			sts, ok := g.Judges[kind]
			if !ok {
				continue
			}
			out = append(out, docCase(cfg, g, kind, sts))
		}
	}
	return out
}

func docCase(cfg DocConfig, g DocGroup, kind string, sts []string) core.Case {
	all := sts
	hasInvalid := len(g.Invalid) > 0 && !g.SkipGeneral
	switch {
	case kind == JudgeConsumer && hasInvalid:
		all = Union(sts, cfg.ConsumerErrors)
	case kind == JudgeProducer && hasInvalid:
		all = Union(sts, cfg.ProducerNonConforming)
	}
	c := core.Case{ID: cfg.Profile + "/document/" + g.Case + "/" + kind, Profile: cfg.Profile, Statements: all}
	switch kind {
	case JudgeConsumer:
		c.Needs = []core.Capability{core.CapDocumentConsumer}
		c.Run = func(_ context.Context, s core.Subject) []core.Observation {
			return runConsumer(cfg, g, sts, all, s.(core.DocumentConsumer))
		}
	case JudgeProducer:
		c.Needs = []core.Capability{core.CapDocumentProducer}
		c.Run = func(_ context.Context, s core.Subject) []core.Observation {
			return runProducer(cfg, g, sts, all, s.(core.DocumentProducer))
		}
	default:
		c.Needs = []core.Capability{core.CapDocumentValidator}
		c.Run = func(_ context.Context, s core.Subject) []core.Observation {
			return runValidator(cfg, g, sts, s.(core.DocumentValidator))
		}
	}
	return c
}

func runConsumer(cfg DocConfig, g DocGroup, sts, all []string, p core.DocumentConsumer) []core.Observation {
	var r Recorder
	for _, f := range g.Valid {
		_, _, err := p.Consume(f.Bytes(), cfg.mediaType(f), cfg.Version, true)
		r.Judge(sts, f.Name, err == nil, "accepted (conforming document)", errText("rejected", err), g.Partial)
	}
	for _, f := range g.Invalid {
		_, _, err := p.Consume(f.Bytes(), cfg.mediaType(f), cfg.Version, true)
		r.Judge(all, f.Name, err != nil, "an error: "+f.Why, "accepted", g.Partial)
	}
	return r.Observations()
}

func runProducer(cfg DocConfig, g DocGroup, sts, all []string, p core.DocumentProducer) []core.Observation {
	var r Recorder
	for _, f := range g.Valid {
		if d, ok := f.Doc(); ok {
			_, _, err := p.Produce(d, cfg.Version)
			r.Judge(sts, f.Name, err == nil, "produced (conforming document)", errText("refused", err), g.Partial)
		}
	}
	for _, f := range g.Invalid {
		if d, ok := f.Doc(); ok {
			data, _, err := p.Produce(d, cfg.Version)
			r.Judge(all, f.Name, err != nil, "refused: "+f.Why, fmt.Sprintf("produced %d bytes", len(data)), g.Partial)
		}
	}
	return r.Observations()
}

func runValidator(cfg DocConfig, g DocGroup, sts []string, p core.DocumentValidator) []core.Observation {
	var r Recorder
	for _, f := range g.Valid {
		if d, ok := f.Doc(); ok {
			fs, err := p.Validate(d, cfg.Version)
			if err != nil {
				r.All(sts, core.Error, f.Name, "validator failed: "+err.Error())
				continue
			}
			r.Judge(sts, f.Name, len(fs) == 0, "no finding (conforming document)", findingsText(fs), g.Partial)
		}
	}
	for _, f := range g.Invalid {
		if d, ok := f.Doc(); ok {
			fs, err := p.Validate(d, cfg.Version)
			if err != nil {
				r.All(sts, core.Error, f.Name, "validator failed: "+err.Error())
				continue
			}
			r.Judge(sts, f.Name, len(fs) > 0, "a finding: "+f.Why, "no finding", g.Partial)
		}
	}
	return r.Observations()
}

func errText(prefix string, err error) string {
	if err == nil {
		return ""
	}
	return prefix + ": " + err.Error()
}

func findingsText(fs []core.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	return fmt.Sprintf("%d finding(s), first %s at %q: %s", len(fs), fs[0].Code, fs[0].Path, fs[0].Message)
}
