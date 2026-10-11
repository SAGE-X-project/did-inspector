// Package fixtures defines the fixture registry: a declarative set of DIDs
// of the fixture DID method "example", each mapped to the stored bytes of
// its DID document versions, their media types and DID document metadata,
// and the state of the DID (deactivated, failing). The registry is the
// verifiable data registry of the fixture method.
//
// Resolution and dereferencing cases need a resolver to run against. The
// inspector does not resolve anything itself: it hands a profile's registry
// to the subject (core.FixtureMethod), and the adapter wires it into the
// subject as the method driver of "example". The subject's own resolver
// and dereferencer then run their algorithms over what the driver returns,
// and the cases judge the results. Read implements the driver's lookup, so
// that every adapter reads the registry the same way.
//
// The package uses the standard library only and imports nothing of the
// inspector, so that adapters in other modules can use it without pulling
// in the inspector's checks.
package fixtures

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Format identifies the registry format and its version.
const Format = "did-inspector-fixture-registry/1"

// Method is the method name of the fixture DID method.
const Method = "example"

// UnsupportedMethod is a method name the inspector uses for DIDs whose
// method the subject must not support. An adapter must not wire a driver
// for it.
const UnsupportedMethod = "inspectorunsupported"

// Registry is the content of a registry file.
type Registry struct {
	// Format is Format.
	Format string `json:"format"`
	// Method is Method.
	Method string `json:"method"`
	// Entries maps each DID of the method to its entry. A DID of the method
	// that has no entry does not exist.
	Entries map[string]Entry `json:"entries"`
}

// Entry is the state of one DID in the registry.
type Entry struct {
	// Deactivated reports that the method has deactivated the DID. The
	// driver still returns the last version, flagged deactivated.
	Deactivated bool `json:"deactivated,omitempty"`
	// Fail, when not empty, makes the driver return an *InjectedError with
	// this message instead of a record: it models an unexpected failure of
	// the method's Read operation.
	Fail string `json:"fail,omitempty"`
	// Versions are the document versions, oldest first. The last one is
	// the current version.
	Versions []Version `json:"versions,omitempty"`
}

// Version is one stored version of a DID document.
type Version struct {
	// VersionID is the version identifier the method assigns.
	VersionID string `json:"versionId"`
	// ValidFrom is the time the version became current, as an XML Schema
	// dateTime in UTC ("2021-05-10T17:00:00Z").
	ValidFrom string `json:"validFrom"`
	// MediaType is the media type the method stores the bytes under.
	MediaType string `json:"mediaType"`
	// Document is the stored representation when it is JSON: its bytes are
	// exactly the JSON text in the registry file.
	Document json.RawMessage `json:"document,omitempty"`
	// Text is the stored representation when it is not JSON (for example
	// malformed bytes). Exactly one of Document and Text is set.
	Text *string `json:"text,omitempty"`
	// Metadata is the DID document metadata the method reports for the
	// version, a JSON object. It does not carry deactivated: the resolver
	// derives that from the entry.
	Metadata json.RawMessage `json:"documentMetadata,omitempty"`
}

// Bytes returns the stored representation.
func (v Version) Bytes() []byte {
	if v.Text != nil {
		return []byte(*v.Text)
	}
	return slices.Clone([]byte(v.Document))
}

// Request is one lookup by a resolver.
type Request struct {
	// DID is the DID to read.
	DID string
	// VersionID, when not empty, selects the version with that id.
	VersionID string
	// VersionTime, when not empty, selects the most recent version that
	// became current at or before that time. It must be an XML Schema
	// dateTime in UTC without fractional seconds.
	VersionTime string
}

// Record is what the driver returns for a request.
type Record struct {
	DID string
	// VersionID is the id of the version returned.
	VersionID string
	// Bytes are the stored representation and MediaType its media type.
	Bytes     []byte
	MediaType string
	// Metadata is the stored DID document metadata, a JSON object.
	Metadata []byte
	// Deactivated reports that the method has deactivated the DID.
	Deactivated bool
}

// Lookup errors.
var (
	// ErrMethodNotSupported: the DID is not of the fixture method.
	ErrMethodNotSupported = errors.New("fixtures: DID is not of method example")
	// ErrNotFound: the DID does not exist.
	ErrNotFound = errors.New("fixtures: DID not found")
	// ErrVersionNotFound: the DID exists but no version matches.
	ErrVersionNotFound = errors.New("fixtures: no version matches")
	// ErrInvalidVersionTime: VersionTime is not a UTC dateTime.
	ErrInvalidVersionTime = errors.New("fixtures: versionTime is not a UTC dateTime without fractional seconds")
)

// InjectedError is the failure an entry with Fail set makes the driver
// return.
type InjectedError struct {
	DID     string
	Message string
}

func (e *InjectedError) Error() string {
	return fmt.Sprintf("fixtures: injected failure reading %s: %s", e.DID, e.Message)
}

// timeLayout is the only dateTime form the registry uses and accepts.
const timeLayout = "2006-01-02T15:04:05Z"

// parseTime accepts exactly the form of timeLayout; time.Parse alone would
// also accept fractional seconds.
func parseTime(s string) (time.Time, error) {
	if len(s) != len(timeLayout) {
		return time.Time{}, fmt.Errorf("%q is not of the form %s", s, timeLayout)
	}
	return time.Parse(timeLayout, s)
}

// Parse reads and validates a registry file.
func Parse(data []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("fixtures: decode registry: %w", err)
	}
	if dec.More() {
		return nil, errors.New("fixtures: trailing data after the registry")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks that the registry is well formed: the format and method
// are known, every DID is of the method, every entry has a version or a
// failure, and every version has an id, a time, a media type, exactly one
// representation and metadata that is a JSON object.
func (r *Registry) Validate() error {
	if r.Format != Format {
		return fmt.Errorf("fixtures: format %q, want %q", r.Format, Format)
	}
	if r.Method != Method {
		return fmt.Errorf("fixtures: method %q, want %q", r.Method, Method)
	}
	var errs []error
	for _, did := range r.DIDs() {
		if err := validateEntry(did, r.Entries[did]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateEntry(did string, e Entry) error {
	if !strings.HasPrefix(did, "did:"+Method+":") || len(did) == len("did:"+Method+":") {
		return fmt.Errorf("fixtures: %q is not a DID of method %s", did, Method)
	}
	if e.Fail == "" && len(e.Versions) == 0 {
		return fmt.Errorf("fixtures: %s has neither versions nor a failure", did)
	}
	ids := map[string]bool{}
	var prev time.Time
	for i, v := range e.Versions {
		where := fmt.Sprintf("fixtures: %s version %d", did, i)
		if v.VersionID == "" || ids[v.VersionID] {
			return fmt.Errorf("%s: empty or repeated versionId %q", where, v.VersionID)
		}
		ids[v.VersionID] = true
		t, err := parseTime(v.ValidFrom)
		if err != nil {
			return fmt.Errorf("%s: validFrom: %w", where, err)
		}
		if i > 0 && !t.After(prev) {
			return fmt.Errorf("%s: validFrom is not after the previous version", where)
		}
		prev = t
		if v.MediaType == "" {
			return fmt.Errorf("%s: empty mediaType", where)
		}
		if (len(v.Document) == 0) == (v.Text == nil) {
			return fmt.Errorf("%s: needs exactly one of document and text", where)
		}
		if !isObject(v.Metadata) {
			return fmt.Errorf("%s: documentMetadata is not a JSON object", where)
		}
	}
	return nil
}

func isObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && m != nil
}

// DIDs returns the DIDs of the registry in lexical order.
func (r *Registry) DIDs() []string {
	out := make([]string, 0, len(r.Entries))
	for did := range r.Entries {
		out = append(out, did)
	}
	slices.Sort(out)
	return out
}

// Read is the lookup of the fixture method driver: it returns the record
// for the request, or an error that the resolver maps to a resolution
// result.
//
//   - A DID of another method: ErrMethodNotSupported.
//   - A DID without an entry: ErrNotFound.
//   - An entry with Fail set: *InjectedError.
//   - VersionID or VersionTime that no version matches: ErrVersionNotFound.
//   - A VersionTime that is not a UTC dateTime: ErrInvalidVersionTime.
//
// Without a version selector Read returns the current version.
func (r *Registry) Read(req Request) (Record, error) {
	if !strings.HasPrefix(req.DID, "did:"+Method+":") {
		return Record{}, ErrMethodNotSupported
	}
	e, ok := r.Entries[req.DID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if e.Fail != "" {
		return Record{}, &InjectedError{DID: req.DID, Message: e.Fail}
	}
	v, err := selectVersion(e.Versions, req)
	if err != nil {
		return Record{}, err
	}
	return Record{
		DID:         req.DID,
		VersionID:   v.VersionID,
		Bytes:       v.Bytes(),
		MediaType:   v.MediaType,
		Metadata:    slices.Clone([]byte(v.Metadata)),
		Deactivated: e.Deactivated,
	}, nil
}

func selectVersion(vs []Version, req Request) (Version, error) {
	candidates := vs
	if req.VersionTime != "" {
		at, err := parseTime(req.VersionTime)
		if err != nil {
			return Version{}, ErrInvalidVersionTime
		}
		var upTo []Version
		for _, v := range vs {
			// ValidFrom was checked by Validate.
			if from, _ := parseTime(v.ValidFrom); !from.After(at) {
				upTo = append(upTo, v)
			}
		}
		candidates = upTo
	}
	if req.VersionID != "" {
		i := slices.IndexFunc(candidates, func(v Version) bool { return v.VersionID == req.VersionID })
		if i < 0 {
			return Version{}, ErrVersionNotFound
		}
		if req.VersionTime == "" || i == len(candidates)-1 {
			return candidates[i], nil
		}
		// The version exists but is not the one current at VersionTime.
		return Version{}, ErrVersionNotFound
	}
	if len(candidates) == 0 {
		return Version{}, ErrVersionNotFound
	}
	return candidates[len(candidates)-1], nil
}
