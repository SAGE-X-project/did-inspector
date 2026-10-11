package gen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/statements/extract"
)

// Scope values.
const (
	ScopeChecked      = "checked"
	ScopeNotCheckable = "not-checkable"
	ScopePending      = "pending"
)

// ScopeFile is the name of the scope decision file in the statements
// directory.
const ScopeFile = "scope.json"

// Decision is the inspector's scope decision for one statement. Level is
// the statement's RFC 2119 level (extract.LevelOf); the generator derives it
// from the statement's keywords and rewrites it on every run, so it is never
// decided by hand.
type Decision struct {
	Scope  string `json:"scope"`
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

// Validate reports whether the decision has a known scope and level and a
// reason.
func (d Decision) Validate() error {
	switch d.Scope {
	case ScopeChecked, ScopeNotCheckable, ScopePending:
	default:
		return fmt.Errorf("unknown scope %q", d.Scope)
	}
	switch d.Level {
	case extract.LevelRequirement, extract.LevelRecommendation:
	default:
		return fmt.Errorf("unknown level %q", d.Level)
	}
	if strings.TrimSpace(d.Reason) == "" {
		return errors.New("missing reason")
	}
	return nil
}

// ScopeEntry pairs a statement id with its decision, for ordered output.
type ScopeEntry struct {
	ID       string
	Decision Decision
}

// Reasons recorded by the initial scope decision.
const (
	reasonInformative     = "informative content (%s); it states no requirement"
	reasonKeywordBoiler   = "defines how RFC 2119 key words are read; it states no requirement on an implementation"
	reasonMethodSpec      = "addressed to DID method specifications, not to an implementation's observable behavior"
	reasonSpecAuthors     = "addressed to specification authors, not to an implementation's observable behavior"
	reasonRegistry        = "addressed to registries and registrants, not to an implementation's observable behavior"
	reasonRepresentation  = "addressed to representation or extension specifications, not to an implementation's observable behavior"
	reasonPermission      = "a permission to the implementation; no observable behavior can violate it"
	reasonShapePermission = "a permission on data content; observable as a conforming consumer or validator accepting such data; no case yet"
	reasonStep            = "an algorithm step; observable through the result of the algorithm; no case yet"
	reasonRequirement     = "a requirement on implementations or the data they produce or accept; no case yet"
	reasonRecommendation  = "a recommendation on implementations or the data they produce or accept; no case yet"
)

// methodSpecSections hold statements addressed to DID method specifications.
var methodSpecSections = map[string]bool{
	"method-syntax": true, "method-operations": true, "security-requirements": true,
	"privacy-requirements": true, "vdr-forks": true, "method-architectures": true,
}

type authorRule struct {
	re     *regexp.Regexp
	reason string
}

var authorRules = []authorRule{
	{regexp.MustCompile(`(?i)method specification|security considerations section|privacy considerations section`), reasonMethodSpec},
	{regexp.MustCompile(`(?i)^(a |the |any )?(applicable )?did methods? |^if a did method `), reasonMethodSpec},
	{regexp.MustCompile(`(?i)specification authors|^a specification that defines|extension specification|representation specification`), reasonSpecAuthors},
	{regexp.MustCompile(`(?i)registered in|be registered|register their|property definitions registered|registries mechanism|extensions mechanism`), reasonRegistry},
	{regexp.MustCompile(`(?i)^a representation |^representations may |^extension mechanisms |^such extension mechanisms |extensions use |^syntaxes used to express`), reasonRepresentation},
}

// behaviorPermission matches permissions granted to an implementation's
// behavior, as opposed to permissions on data content.
var behaviorPermission = regexp.MustCompile(`(?i)implement|support|conforming (producer|consumer)|resolver|dereferencer|client|algorithm|metadata may|tls|interoperability is not guaranteed`)

var keywordBoilerplate = regexp.MustCompile(`(?i)^the key words .* are to be interpreted`)

var permissionKeywords = []string{"MAY", "OPTIONAL", "NOT REQUIRED"}

// InitialDecision returns the inspector's first scope decision for a
// statement: not-checkable for informative statements, statements addressed
// to specification authors, method specifications, registries,
// representation or extension specifications, and permissions with no
// observable effect; pending for everything else, recommendations included.
// The decision carries the statement's level.
func InitialDecision(st extract.Statement) Decision {
	d := initialScope(st)
	d.Level = extract.LevelOf(st.Keywords)
	return d
}

func initialScope(st extract.Statement) Decision {
	if st.Informative {
		return Decision{Scope: ScopeNotCheckable, Reason: fmt.Sprintf(reasonInformative, st.InformativeReason)}
	}
	if keywordBoilerplate.MatchString(st.Text) {
		return Decision{Scope: ScopeNotCheckable, Reason: reasonKeywordBoiler}
	}
	if methodSpecSections[st.Section] {
		return Decision{Scope: ScopeNotCheckable, Reason: reasonMethodSpec}
	}
	for _, r := range authorRules {
		if r.re.MatchString(st.Text) {
			return Decision{Scope: ScopeNotCheckable, Reason: r.reason}
		}
	}
	if isPermission(st.Keywords) {
		if behaviorPermission.MatchString(st.Text) {
			return Decision{Scope: ScopeNotCheckable, Reason: reasonPermission}
		}
		return Decision{Scope: ScopePending, Reason: reasonShapePermission}
	}
	if st.Kind == extract.KindStep {
		return Decision{Scope: ScopePending, Reason: reasonStep}
	}
	if extract.LevelOf(st.Keywords) == extract.LevelRecommendation {
		return Decision{Scope: ScopePending, Reason: reasonRecommendation}
	}
	return Decision{Scope: ScopePending, Reason: reasonRequirement}
}

func isPermission(kws []string) bool {
	if len(kws) == 0 {
		return false
	}
	for _, k := range kws {
		if !slices.Contains(permissionKeywords, k) {
			return false
		}
	}
	return true
}

// StaleScopeError lists scope entries whose statements no longer exist.
type StaleScopeError struct {
	IDs []string
}

func (e *StaleScopeError) Error() string {
	return fmt.Sprintf("%s has %d entries for statements that no longer exist: %s", ScopeFile, len(e.IDs), strings.Join(e.IDs, ", "))
}

// MergeScope keeps every existing decision for a statement that still
// exists, adds the initial decision for each new statement, sets every
// decision's level from its statement's keywords, and returns the entries
// in statement order. Existing decisions for statements that no
// longer exist are an error unless prune is set, in which case they are
// dropped.
func MergeScope(docs []Document, existing map[string]Decision, prune bool) ([]ScopeEntry, error) {
	known := map[string]bool{}
	var out []ScopeEntry
	for _, d := range docs {
		for _, st := range d.Statements {
			known[st.ID] = true
			dec, ok := existing[st.ID]
			if !ok {
				dec = InitialDecision(st)
			}
			dec.Level = extract.LevelOf(st.Keywords)
			out = append(out, ScopeEntry{ID: st.ID, Decision: dec})
		}
	}
	var stale []string
	for id := range existing {
		if !known[id] {
			stale = append(stale, id)
		}
	}
	if len(stale) > 0 && !prune {
		slices.Sort(stale)
		return nil, &StaleScopeError{IDs: stale}
	}
	return out, nil
}

// EncodeScope renders scope entries as a JSON object whose members follow
// the given order, one member per line.
func EncodeScope(entries []ScopeEntry) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, e := range entries {
		if err := e.Decision.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID, err)
		}
		key, err := marshalNoEscape(e.ID)
		if err != nil {
			return nil, err
		}
		val, err := marshalNoEscape(e.Decision)
		if err != nil {
			return nil, err
		}
		buf.WriteString("  ")
		buf.Write(key)
		buf.WriteString(": ")
		buf.Write(val)
		if i < len(entries)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// DecodeScope parses a scope file.
func DecodeScope(data []byte) (map[string]Decision, error) {
	var m map[string]Decision
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode %s: %w", ScopeFile, err)
	}
	return m, nil
}

// ReadScope reads a scope file; a missing file is an empty scope.
func ReadScope(path string) (map[string]Decision, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Decision{}, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeScope(data)
}
