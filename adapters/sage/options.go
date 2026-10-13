package sage

import (
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"time"
)

// nativeOptions translates types without fixing or validating input. Wrong
// types remain under their modeled name in Extra, so the actual subject can
// reject them. versionTime retains its offset and sub-second precision.
// An Options entry takes precedence over the old shorthand fields.
func nativeOptions(q sageresolution.Request) (resolution.ResolutionOptions, resolution.DereferenceOptions) {
	ro := resolution.ResolutionOptions{Accept: q.Accept}
	do := resolution.DereferenceOptions{Accept: q.Accept, VerificationRelationship: q.Relationship}
	for name, value := range q.Options {
		if !setResolveOption(&ro, name, value) {
			if ro.Extra == nil {
				ro.Extra = map[string]any{}
			}
			ro.Extra[name] = value
		}
		s, ok := value.(string)
		switch {
		case name == "accept" && ok:
			do.Accept = s
		case name == "verificationRelationship" && ok:
			do.VerificationRelationship = s
		default:
			if do.Extra == nil {
				do.Extra = map[string]any{}
			}
			do.Extra[name] = value
		}
	}
	return ro, do
}
func setResolveOption(o *resolution.ResolutionOptions, name string, value any) bool {
	switch name {
	case "accept":
		s, ok := value.(string)
		o.Accept = s
		return ok
	case "expandRelativeUrls":
		v, ok := value.(bool)
		o.ExpandRelativeURLs = v
		return ok
	case "noCache":
		v, ok := value.(bool)
		o.NoCache = v
		return ok
	case "versionId":
		s, ok := value.(string)
		o.VersionID = s
		return ok
	case "versionTime":
		s, ok := value.(string)
		if !ok {
			return false
		}
		// Go's time parser accepts a comma and truncates precision beyond
		// nanoseconds. Keep such original strings in Extra rather than changing
		// their grammar or value while translating to the typed subject API.
		if strings.Contains(s, ",") {
			return false
		}
		if dot := strings.IndexByte(s, '.'); dot >= 0 {
			digits := 0
			for _, c := range s[dot+1:] {
				if c < '0' || c > '9' {
					break
				}
				digits++
			}
			if digits > 9 {
				return false
			}
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return false
		}
		o.VersionTime = &t
		return true
	}
	return false
}
