package sageresolution

import (
	"errors"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// An absent optional property does not establish its conditional format rule.
var errAbsentMetadata = errors.New("conditional metadata property absent; no format judgment")

func checkMetadata(o Result, md, cm core.DocumentJSON, w expected) (bool, error) {
	var wire checks.BindingResult
	if o.Exchange != nil {
		ex := o.Exchange
		if _, err := parse(ex.Body); err != nil {
			return false, err
		}
		var err error
		switch checks.MediaTypeEssence(ex.Header.Get("Content-Type")) {
		case checks.MediaTypeDIDResolution:
			wire, err = checks.ParseResolutionResult(ex.Body)
		case checks.MediaTypeDIDURLDereferencing:
			wire, err = checks.ParseDereferencingResult(ex.Body)
		default:
			return false, fmt.Errorf("metadata inspection requires a complete HTTP result")
		}
		if err != nil {
			return false, err
		}
		md, cm = wire.Metadata, wire.ContentMetadata
		if e, present := md.Get("error"); present {
			typ, _ := e.Get("type")
			if e.Kind != core.KindObject || typ.Kind != core.KindString || !checks.IsAbsoluteURI(typ.Str) {
				return false, fmt.Errorf("malformed wire metadata error")
			}
		}
	}
	field, object := "contentType", md
	switch w.Check {
	case "version-ascii":
		field, object = "versionId", cm
	case "legacy-keyword", "prefixed-error":
		field = "error"
	}
	value, present := object.Get(field)
	if w.Check == "dereference-media-type" {
		if o.Exchange == nil {
			return false, fmt.Errorf("dereferencing media observation requires wire content")
		}
		if _, failed := md.Get("error"); !wire.HasContent || failed {
			return false, errAbsentMetadata
		}
		if !present {
			return false, nil
		}
	} else if !present {
		return false, errAbsentMetadata
	}
	switch w.Check {
	case "version-ascii", "content-type-ascii":
		return value.Kind == core.KindString && checks.IsASCII(value.Str), nil
	case "resolution-media-type", "dereference-media-type":
		expected, ok := w.Value.(string)
		if !ok || (expected != "application/did" && expected != "application/did+json" && expected != "application/json") {
			return false, fmt.Errorf("invalid expected fixture media type")
		}
		if value.Kind != core.KindString || !checks.IsASCII(value.Str) || !checks.IsMediaType(value.Str) || checks.MediaTypeEssence(value.Str) != expected {
			return false, nil
		}
		content, hasContent := wire.Content, wire.HasContent
		if o.Exchange == nil {
			d, err := parse(o.Raw)
			if err != nil {
				return false, nil
			}
			content, hasContent = d.Value(), o.HasContent
		}
		id, _ := content.Get("id")
		validID := id.Kind == core.KindString && checks.IsDID(id.Str)
		if w.Check == "dereference-media-type" {
			validID = id.Kind == core.KindString && checks.IsDIDURL(id.Str)
		}
		if !hasContent || content.Kind != core.KindObject || !validID || errorName(md) != "" {
			return false, nil
		}
		if expected == "application/did" {
			ctx, _ := content.Get("@context")
			if ctx.Kind == core.KindArray && len(ctx.Array) > 0 {
				ctx = ctx.Array[0]
			}
			return ctx.Kind == core.KindString && ctx.Str == "https://www.w3.org/ns/did/v1.1", nil
		}
		return true, nil
	case "legacy-keyword":
		return value.Kind == core.KindString && checks.IsKeyword(value.Str), nil
	case "prefixed-error":
		// These cases trigger only standard-defined keyword errors. Extension
		// error URLs are not required to use the standard namespace.
		typ, _ := value.Get("type")
		keyword, ok := w.Value.(string)
		if !ok || !checks.IsKeyword(keyword) {
			return false, fmt.Errorf("invalid expected error keyword")
		}
		return value.Kind == core.KindObject && typ.Kind == core.KindString && typ.Str == "https://www.w3.org/ns/did#"+keyword, nil
	}
	return false, fmt.Errorf("unknown metadata check %q", w.Check)
}
