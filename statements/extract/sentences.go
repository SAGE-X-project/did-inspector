package extract

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Keyword markers wrap the text of an RFC 2119 keyword element while a block
// is being collected, so that sentence splitting keeps track of which
// sentences carry a keyword.
const (
	kwOpen  = '\x01'
	kwClose = '\x02'
)

// abbreviations end with a period that does not end a sentence.
var abbreviations = map[string]bool{
	"e.g": true, "i.e": true, "cf": true, "vs": true, "al": true,
	"fig": true, "sec": true, "no": true, "approx": true,
}

// collapseSpace replaces every run of white space with one space and trims
// the result.
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// splitSentences splits normalised text into sentences. A sentence ends at
// '.', '!' or '?', optionally followed by closing quotes or brackets, when
// the next character after a space starts a new sentence (an upper-case
// letter, a digit, an opening quote or bracket, or a keyword marker) and the
// word before the period is not a known abbreviation.
func splitSentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		end := i
		for end < len(text) {
			c, cs := utf8.DecodeRuneInString(text[end:])
			if !isClosingPunct(c) {
				break
			}
			end += cs
		}
		if end >= len(text) {
			break
		}
		if text[end] != ' ' || end+1 >= len(text) {
			continue
		}
		nextRune, _ := utf8.DecodeRuneInString(text[end+1:])
		if !startsSentence(nextRune) {
			continue
		}
		if r == '.' && isAbbreviation(text[start:i-1]) {
			continue
		}
		out = appendSentence(out, text[start:end])
		start = end + 1
		i = start
	}
	return appendSentence(out, text[start:])
}

func appendSentence(out []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	return append(out, s)
}

func isClosingPunct(r rune) bool {
	switch r {
	case '"', '\'', ')', ']', '”', '’', kwClose:
		return true
	}
	return false
}

func startsSentence(r rune) bool {
	switch r {
	case '"', '\'', '(', '[', '“', '‘', kwOpen:
		return true
	}
	return unicode.IsUpper(r) || unicode.IsDigit(r)
}

// isAbbreviation reports whether the word that ends prefix is a known
// abbreviation.
func isAbbreviation(prefix string) bool {
	idx := strings.LastIndexAny(prefix, " ( ")
	word := strings.ToLower(prefix[idx+1:])
	return abbreviations[word]
}

// keywordsOf returns the RFC 2119 keywords marked in s, in order of first
// appearance, and s with the markers removed.
func keywordsOf(s string) ([]string, string) {
	var kws []string
	seen := map[string]bool{}
	var plain strings.Builder
	for {
		open := strings.IndexRune(s, kwOpen)
		if open < 0 {
			plain.WriteString(s)
			break
		}
		plain.WriteString(s[:open])
		rest := s[open+1:]
		closeIdx := strings.IndexRune(rest, kwClose)
		if closeIdx < 0 {
			plain.WriteString(rest)
			break
		}
		kw := collapseSpace(rest[:closeIdx])
		plain.WriteString(rest[:closeIdx])
		if kw != "" && !seen[kw] {
			seen[kw] = true
			kws = append(kws, kw)
		}
		s = rest[closeIdx+1:]
	}
	return kws, plain.String()
}
