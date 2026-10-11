// Package gen pins the W3C publications the inspector judges against and
// generates the statement files of package statements from their bytes.
package gen

// Source is one pinned publication.
type Source struct {
	// Key is the spec key used in statement ids.
	Key string
	// Title is the publication's title.
	Title string
	// URL is the dated URL of the publication.
	URL string
	// File is the file name under sources/.
	File string
	// SHA256 is the pinned hex SHA-256 of the file.
	SHA256 string
}

// Spec keys of the pinned publications.
const (
	KeyCore10 = "core10"
	KeyDID11  = "did11-cr20260305"
	KeyCID10  = "cid10"
	KeyRes10  = "res10-crd20261001"
)

var sources = []Source{
	{
		Key:    KeyCore10,
		Title:  "Decentralized Identifiers (DIDs) v1.0, W3C Recommendation 19 July 2022",
		URL:    "https://www.w3.org/TR/2022/REC-did-core-20220719/",
		File:   "did-core-1.0-20220719.html",
		SHA256: "5e44345740d9bfaa852d3b66c57e98c9beb6c5bf6083b0126dd5daac377b9993",
	},
	{
		Key:    KeyDID11,
		Title:  "Decentralized Identifiers (DIDs) v1.1, W3C Candidate Recommendation Snapshot 5 March 2026",
		URL:    "https://www.w3.org/TR/2026/CR-did-1.1-20260305/",
		File:   "did-core-1.1-cr-20260305.html",
		SHA256: "4a48022defe07d37d2decc3ec9027a932dc883b2ad164a5aeaf9256e530bd979",
	},
	{
		Key:    KeyCID10,
		Title:  "Controlled Identifiers v1.0, W3C Recommendation 15 May 2025",
		URL:    "https://www.w3.org/TR/2025/REC-cid-1.0-20250515/",
		File:   "controlled-identifiers-1.0-20250515.html",
		SHA256: "c5e9befba602b53de46669cf98067123d1901357a425f8bff621796b2ac4ac4a",
	},
	{
		Key:    KeyRes10,
		Title:  "DID Resolution v1.0, W3C Candidate Recommendation Draft 1 October 2026",
		URL:    "https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/",
		File:   "did-resolution-1.0-crd-20261001.html",
		SHA256: "2b194843d37f5b7f01a4f5464f64d672dc4be43dafe5f2f49114c6070819586e",
	},
}

// Sources returns the pinned publications in a fixed order.
func Sources() []Source {
	out := make([]Source, len(sources))
	copy(out, sources)
	return out
}

// SourceByKey returns the pinned publication with the given spec key.
func SourceByKey(key string) (Source, bool) {
	for _, s := range sources {
		if s.Key == key {
			return s, true
		}
	}
	return Source{}, false
}
