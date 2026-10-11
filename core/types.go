package core

// DIDParts are the components of a DID as a subject reports them.
type DIDParts struct {
	// DID is the whole DID.
	DID string `json:"did"`
	// Method is the method-name.
	Method string `json:"method"`
	// MethodSpecificID is the method-specific-id.
	MethodSpecificID string `json:"method_specific_id"`
}

// DIDURLParts are the components of a DID URL as a subject reports them.
// HasQuery and HasFragment distinguish an empty component ("did:x:y?") from
// an absent one ("did:x:y").
type DIDURLParts struct {
	DIDURL      string   `json:"did_url"`
	DID         DIDParts `json:"did"`
	Path        string   `json:"path"`
	Query       string   `json:"query"`
	HasQuery    bool     `json:"has_query"`
	Fragment    string   `json:"fragment"`
	HasFragment bool     `json:"has_fragment"`
}

// ConsumeInfo is what a subject reports about a consumed representation.
type ConsumeInfo struct {
	// MediaType is the media type the subject used to choose the
	// representation.
	MediaType string `json:"media_type"`
	// Version is the DID version the subject decided the document has.
	Version string `json:"version"`
	// RepresentationEntries is the representation-specific entries map the
	// subject returned, for example the @context entry.
	RepresentationEntries DocumentJSON `json:"representation_entries"`
	// Notes are any further messages the subject reported.
	Notes []string `json:"notes,omitempty"`
}

// Finding is one problem a subject's validator reported.
type Finding struct {
	// Code is the subject's identifier for the problem.
	Code string `json:"code"`
	// Path locates the problem in the document, as a JSON Pointer.
	Path string `json:"path"`
	// Message is the subject's description.
	Message string `json:"message"`
}

// ResolutionResult is the result of DID resolution as a subject produced
// it. Raw holds the bytes the subject produced (a representation of the DID
// document, or a whole DID resolution result) and MediaType the media type
// it declared for them, so the inspector can check the bytes itself.
type ResolutionResult struct {
	ResolutionMetadata DocumentJSON `json:"did_resolution_metadata"`
	// Document is nil when the subject returned no DID document.
	Document         *DocumentJSON `json:"did_document"`
	DocumentMetadata DocumentJSON  `json:"did_document_metadata"`
	Raw              []byte        `json:"raw,omitempty"`
	MediaType        string        `json:"media_type,omitempty"`
}

// DereferenceResult is the result of DID URL dereferencing as a subject
// produced it. Content holds the raw content stream and MediaType the media
// type the subject declared for it.
type DereferenceResult struct {
	DereferencingMetadata DocumentJSON `json:"dereferencing_metadata"`
	Content               []byte       `json:"content_stream,omitempty"`
	MediaType             string       `json:"media_type,omitempty"`
	ContentMetadata       DocumentJSON `json:"content_metadata"`
}

// RetrievalResult is the result of Retrieve Verification Method (CID 1.0
// §3.3) as a subject produced it: the verification method it returned, or
// the error it raised.
type RetrievalResult struct {
	// VerificationMethod is nil when the subject returned no method.
	VerificationMethod *DocumentJSON `json:"verification_method,omitempty"`
	// Error is nil when the subject raised no error.
	Error *ProcessingError `json:"error,omitempty"`
}

// ProcessingError is an error a subject raised in an algorithm, with the
// error type it conveyed (a URL such as
// "https://w3id.org/security#INVALID_VERIFICATION_METHOD", or empty when it
// conveyed none).
type ProcessingError struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
}
