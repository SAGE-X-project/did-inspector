// Package extract derives normative statements from a W3C publication.
//
// It reads the publication's HTML with a small hand-written tokenizer and
// produces two kinds of statements:
//
//   - requirement: a sentence that contains an RFC 2119 keyword, marked in
//     the publication as <em class="rfc2119">;
//   - step: one step of an algorithm, an <li> of an <ol class="algorithm">
//     or of a list nested inside such a step, linked to its parent step.
//
// Each statement records the id of the enclosing section, its term (the <dt>
// term when it sits in a <dd>, or the first cell of the table row when it sits
// in a later cell of that row), and whether it is informative: inside an element with one
// of the classes informative, note, example, issue or advisement, or inside a
// section that says "This section is non-normative". The section with id
// "conformance" is normative even inside an informative section.
package extract

import (
	"fmt"
	"slices"
	"strings"
)

// Statement kinds.
const (
	KindRequirement = "requirement"
	KindStep        = "step"
)

// Statement is one statement extracted from a publication.
type Statement struct {
	ID                string   `json:"id"`
	Section           string   `json:"section"`
	Kind              string   `json:"kind"`
	Keywords          []string `json:"keywords,omitempty"`
	Text              string   `json:"text"`
	Term              string   `json:"term,omitempty"`
	Parent            string   `json:"parent,omitempty"`
	Informative       bool     `json:"informative,omitempty"`
	InformativeReason string   `json:"informative_reason,omitempty"`
}

// noSection is the section name used for content outside any section with
// an id.
const noSection = "_"

// informativeClasses mark an element and its content as informative.
var informativeClasses = []string{"informative", "note", "example", "issue", "advisement"}

// conformanceSection is the id of the section that states conformance.
const conformanceSection = "conformance"

// nonNormativeSentence marks the enclosing section as informative.
const nonNormativeSentence = "This section is non-normative"

// blockElements collect their own text. Text inside a nested block belongs
// to the nested block.
var blockElements = map[string]bool{
	"p": true, "li": true, "dd": true, "dt": true, "td": true, "th": true,
	"div": true, "blockquote": true, "caption": true, "figcaption": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
}

// skippedElements hold no statements: code, scripts, styles, document
// metadata, the table of contents and drawings.
var skippedElements = map[string]bool{
	"pre": true, "script": true, "style": true, "head": true, "nav": true,
	"svg": true, "math": true, "template": true,
}

// voidElements never have content or an end tag.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

type section struct {
	id           string
	nonNormative bool
}

type block struct {
	seq         int
	step        bool
	parent      *block
	section     string
	sections    []*section
	informative string
	term        string
	text        strings.Builder
	stmt        *Statement
}

// frame is one open element.
type frame struct {
	name        string
	algorithm   bool             // an <ol class="algorithm">
	informative string           // why the element is informative, if it is
	section     *section         // set for <section>
	block       *block           // set when the element collects its own text
	keyword     bool             // an <em class="rfc2119">
	skip        bool             // content is ignored
	dlTerm      *string          // for <dl>: the text of the latest <dt>
	rowTerm     *string          // for <tr>: the text of the first cell
	cells       int              // for <tr>: cells opened so far
	term        *strings.Builder // collects a <dt> or first cell's text
	termFor     *string          // where the collected term is stored
	context     string           // for <dd> and later cells: their term
	hasContext  bool
}

type pendingStatement struct {
	seq  int
	sub  int
	stmt *Statement
	blk  *block
}

type extractor struct {
	key     string
	stack   []*frame
	seq     int
	pending []pendingStatement
}

// Extract returns the statements of the publication src under the spec key.
// Statement ids have the form "<key>#<section>.<n>", where n counts the
// statements of that section in document order starting at 1.
func Extract(key string, src []byte) ([]Statement, error) {
	if key == "" {
		return nil, fmt.Errorf("extract: empty spec key")
	}
	e := &extractor{key: key}
	tz := newTokenizer(string(src))
	for {
		tok, ok := tz.next()
		if !ok {
			break
		}
		switch tok.typ {
		case startTagToken, selfClosingTagToken:
			e.open(tok)
			if tok.typ == selfClosingTagToken || voidElements[tok.name] {
				e.close(tok.name)
			}
		case endTagToken:
			e.close(tok.name)
		case textToken:
			e.text(tok.data)
		}
	}
	for len(e.stack) > 0 {
		e.closeTop()
	}
	return e.finish(), nil
}

func classTokens(attrs map[string]string) []string {
	return strings.Fields(attrs["class"])
}

func (e *extractor) skipping() bool {
	for _, f := range e.stack {
		if f.skip {
			return true
		}
	}
	return false
}

func (e *extractor) open(tok token) {
	f := &frame{name: tok.name}
	classes := classTokens(tok.attrs)
	if skippedElements[tok.name] {
		f.skip = true
	}
	for _, c := range informativeClasses {
		if slices.Contains(classes, c) {
			f.informative = "class " + c
			break
		}
	}
	switch tok.name {
	case "section":
		f.section = &section{id: tok.attrs["id"]}
	case "ol":
		f.algorithm = slices.Contains(classes, "algorithm")
	case "em":
		f.keyword = slices.Contains(classes, "rfc2119")
	case "dl":
		f.dlTerm = new(string)
	case "dt":
		if dl := e.nearest(func(x *frame) bool { return x.dlTerm != nil }); dl != nil {
			f.term, f.termFor = &strings.Builder{}, dl.dlTerm
		}
	case "dd":
		if dl := e.nearest(func(x *frame) bool { return x.dlTerm != nil }); dl != nil {
			f.context, f.hasContext = *dl.dlTerm, true
		}
	case "tr":
		f.rowTerm = new(string)
	case "td", "th":
		e.openCell(f)
	}
	e.stack = append(e.stack, f)
	if !f.skip && !e.skipping() {
		e.maybeOpenBlock(f)
	}
}

// openCell makes the first cell of a row the term of the row's later cells.
func (e *extractor) openCell(f *frame) {
	tr := e.nearest(func(x *frame) bool { return x.rowTerm != nil })
	if tr == nil {
		return
	}
	tr.cells++
	if tr.cells == 1 {
		f.term, f.termFor = &strings.Builder{}, tr.rowTerm
		return
	}
	f.context, f.hasContext = *tr.rowTerm, true
}

// maybeOpenBlock decides whether the element just pushed collects its own
// text, and whether that text is an algorithm step.
func (e *extractor) maybeOpenBlock(f *frame) {
	step := e.enclosingStep()
	if f.name == "li" && (e.parentIsAlgorithm() || step != nil) {
		e.startBlock(f, true, step)
		return
	}
	if !blockElements[f.name] {
		return
	}
	// Inside a step, nested paragraphs and similar elements are part of the
	// step's text, unless they are informative (a note inside a step).
	if step != nil && f.informative == "" {
		return
	}
	e.startBlock(f, false, nil)
}

// parentIsAlgorithm reports whether the element below the top of the stack
// is an algorithm list.
func (e *extractor) parentIsAlgorithm() bool {
	if len(e.stack) < 2 {
		return false
	}
	return e.stack[len(e.stack)-2].algorithm
}

// enclosingStep returns the innermost open step, or nil if the innermost
// open block (or an informative element above it) is not a step.
func (e *extractor) enclosingStep() *block {
	for i := len(e.stack) - 2; i >= 0; i-- {
		f := e.stack[i]
		if f.informative != "" && (f.block == nil || !f.block.step) {
			return nil
		}
		if f.block != nil {
			if f.block.step {
				return f.block
			}
			return nil
		}
	}
	return nil
}

func (e *extractor) nearest(pred func(*frame) bool) *frame {
	for i := len(e.stack) - 1; i >= 0; i-- {
		if pred(e.stack[i]) {
			return e.stack[i]
		}
	}
	return nil
}

func (e *extractor) startBlock(f *frame, step bool, parent *block) {
	e.seq++
	b := &block{seq: e.seq, step: step, parent: parent, section: noSection}
	normative := false
	for i := len(e.stack) - 1; i >= 0; i-- {
		x := e.stack[i]
		if !normative && b.informative == "" && x.informative != "" {
			b.informative = x.informative
		}
		if x.section == nil {
			continue
		}
		if b.section == noSection && x.section.id != "" {
			b.section = x.section.id
		}
		if !normative {
			b.sections = append(b.sections, x.section)
		}
		// The conformance section is normative even when it is nested in
		// an informative introduction, as publications built with ReSpec
		// define; informative markers outside it do not apply.
		if x.section.id == conformanceSection {
			normative = true
		}
	}
	if c := e.nearest(func(x *frame) bool { return x.hasContext }); c != nil {
		b.term = c.context
	}
	f.block = b
}

func (e *extractor) text(s string) {
	if e.skipping() {
		return
	}
	for _, f := range e.stack {
		if f.term != nil {
			f.term.WriteString(s)
		}
	}
	top := e.nearest(func(x *frame) bool { return x.block != nil })
	if top == nil {
		return
	}
	if e.nearest(func(x *frame) bool { return x.keyword }) != nil {
		top.block.text.WriteRune(kwOpen)
		top.block.text.WriteString(s)
		top.block.text.WriteRune(kwClose)
		return
	}
	top.block.text.WriteString(s)
}

// close pops elements up to and including the innermost open element with
// the given name. An end tag with no open element is ignored.
func (e *extractor) close(name string) {
	idx := -1
	for i := len(e.stack) - 1; i >= 0; i-- {
		if e.stack[i].name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	for len(e.stack) > idx {
		e.closeTop()
	}
}

func (e *extractor) closeTop() {
	f := e.stack[len(e.stack)-1]
	e.stack = e.stack[:len(e.stack)-1]
	if f.term != nil {
		*f.termFor = collapseSpace(f.term.String())
	}
	if f.block != nil {
		e.flush(f.block)
	}
}

// flush turns a finished block into statements.
func (e *extractor) flush(b *block) {
	text := collapseSpace(b.text.String())
	_, plainAll := keywordsOf(text)
	if strings.Contains(plainAll, nonNormativeSentence) && len(b.sections) > 0 {
		b.sections[0].nonNormative = true
	}
	if b.step {
		kws, plain := keywordsOf(text)
		if plain == "" {
			return
		}
		b.stmt = &Statement{Kind: KindStep, Keywords: kws, Text: plain}
		e.pending = append(e.pending, pendingStatement{seq: b.seq, stmt: b.stmt, blk: b})
		return
	}
	for i, s := range splitSentences(text) {
		kws, plain := keywordsOf(s)
		if len(kws) == 0 {
			continue
		}
		st := &Statement{Kind: KindRequirement, Keywords: kws, Text: plain}
		e.pending = append(e.pending, pendingStatement{seq: b.seq, sub: i, stmt: st, blk: b})
	}
}

// finish orders the statements by document position, numbers them per
// section, links steps to their parents and marks informative statements.
func (e *extractor) finish() []Statement {
	slices.SortStableFunc(e.pending, func(a, b pendingStatement) int {
		if a.seq != b.seq {
			return a.seq - b.seq
		}
		return a.sub - b.sub
	})
	counts := map[string]int{}
	for _, p := range e.pending {
		counts[p.blk.section]++
		p.stmt.Section = p.blk.section
		p.stmt.ID = fmt.Sprintf("%s#%s.%d", e.key, p.blk.section, counts[p.blk.section])
		p.stmt.Term = p.blk.term
		reason := informativeReason(p.blk)
		p.stmt.Informative = reason != ""
		p.stmt.InformativeReason = reason
	}
	out := make([]Statement, 0, len(e.pending))
	for _, p := range e.pending {
		if p.stmt.Kind == KindStep {
			for anc := p.blk.parent; anc != nil; anc = anc.parent {
				if anc.stmt != nil {
					p.stmt.Parent = anc.stmt.ID
					break
				}
			}
		}
		out = append(out, *p.stmt)
	}
	return out
}

func informativeReason(b *block) string {
	if b.informative != "" {
		return b.informative
	}
	for _, s := range b.sections {
		if s.nonNormative {
			if s.id == "" {
				return "non-normative section"
			}
			return "non-normative section " + s.id
		}
	}
	return ""
}
