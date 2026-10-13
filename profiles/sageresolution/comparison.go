package sageresolution

import (
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func checkHTTPNative(o Result, w expected) (bool, error) {
	if o.Exchange == nil || o.Native == nil || o.Native.Result == nil {
		return false, fmt.Errorf("missing actual wire or native observation")
	}
	ex, native := o.Exchange, o.Native.Result
	if _, err := parse(ex.Body); err != nil {
		return false, err
	}
	var wire checks.BindingResult
	var err error
	expectedFunction, ok := w.Value.(string)
	if !ok || expectedFunction != o.Native.Request.Function {
		return false, fmt.Errorf("native operation mismatch")
	}
	switch expectedFunction {
	case "resolve":
		if checks.MediaTypeEssence(ex.Header.Get("Content-Type")) != checks.MediaTypeDIDResolution {
			return false, nil
		}
		wire, err = checks.ParseResolutionResult(ex.Body)
	case "dereference":
		if checks.MediaTypeEssence(ex.Header.Get("Content-Type")) != checks.MediaTypeDIDURLDereferencing {
			return false, nil
		}
		wire, err = checks.ParseDereferencingResult(ex.Body)
	default:
		return false, fmt.Errorf("unknown comparison operation")
	}
	if err != nil {
		return false, err
	}
	md, err := parse(native.Metadata)
	if err != nil {
		return false, err
	}
	cm, err := parse(native.ContentMetadata)
	if err != nil {
		return false, err
	}
	if _, failed := md.Get("error"); failed {
		return false, fmt.Errorf("native error comparisons are outside this scope")
	}
	if _, failed := wire.Metadata.Get("error"); failed {
		return false, nil
	}
	if native.HasContent != wire.HasContent {
		return false, nil
	}
	if !equalObserved(md.Value(), wire.Metadata.Value(), "metadata") {
		return false, nil
	}
	if !equalObserved(cm.Value(), wire.ContentMetadata.Value(), "metadata") {
		return false, nil
	}
	if !native.HasContent {
		return wire.Content.Kind == core.KindNull, nil
	}
	content, err := parse(native.Snapshot)
	if err != nil {
		return false, err
	}
	kind := "document"
	if expectedFunction == "dereference" && native.ContentKind == "verification-method" {
		kind = "method"
	}
	return equalObserved(content.Value(), wire.Content, kind), nil
}

// Known DID sets ignore order; unknown extension arrays remain ordered. Singleton
// alternatives are equivalent only where the property explicitly allows both.
func equalObserved(a, b core.Value, kind string) bool {
	setElement, singleton := "", false
	switch kind {
	case "method-set", "relationship-set":
		setElement = "method"
	case "service-set":
		setElement = "service"
	case "set":
		setElement = "unknown"
	case "single-or-set":
		setElement = "unknown"
		singleton = true
	}
	if setElement != "" {
		if !singleton && (a.Kind != core.KindArray || b.Kind != core.KindArray) {
			return false
		}
		left, right := a.Array, b.Array
		if a.Kind != core.KindArray {
			left = []core.Value{a}
		}
		if b.Kind != core.KindArray {
			right = []core.Value{b}
		}
		if len(left) != len(right) {
			return false
		}
		used := make([]bool, len(right))
		for _, item := range left {
			found := false
			for i, candidate := range right {
				if !used[i] && equalObserved(item, candidate, setElement) {
					used[i] = true
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == core.KindObject {
		if len(a.Object) != len(b.Object) {
			return false
		}
		for _, member := range a.Object {
			got, ok := b.Get(member.Name)
			if !ok || !equalObserved(member.Value, got, comparisonKind(kind, member.Name)) {
				return false
			}
		}
		return true
	}
	equal, _ := checks.EqualJSON(a, b)
	return equal
}
func comparisonKind(parent, field string) string {
	if parent == "document" {
		switch field {
		case "controller":
			return "single-or-set"
		case "alsoKnownAs":
			return "set"
		case "verificationMethod":
			return "method-set"
		case "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation":
			return "relationship-set"
		case "service":
			return "service-set"
		}
	}
	if parent == "service" && (field == "type" || field == "serviceEndpoint") {
		return "single-or-set"
	}
	if parent == "metadata" && (field == "equivalentId" || field == "proof") {
		return "set"
	}
	return "unknown"
}
