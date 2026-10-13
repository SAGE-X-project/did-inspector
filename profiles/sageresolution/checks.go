package sageresolution

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
)

func parse(raw []byte) (core.DocumentJSON, error) {
	d, err := core.ParseDocumentJSON(raw)
	if err != nil {
		return d, err
	}
	if len(checks.DuplicateMembers(d.Value())) != 0 {
		return d, fmt.Errorf("duplicate result members")
	}
	return d, nil
}
func judge(out Result, wants []expected, input string) []core.Observation {
	raw, _ := json.Marshal(out)
	var md, cm core.DocumentJSON
	var err error
	if out.Exchange == nil {
		md, err = parse(out.Metadata)
		if err == nil {
			cm, err = parse(out.ContentMetadata)
		}
		if err == nil {
			value, present := md.Get("error")
			legacy := len(wants) > 0 && len(wants[0].Statements) > 0 && strings.HasPrefix(wants[0].Statements[0], "core10#")
			if present {
				if legacy {
					if value.Kind != core.KindString || value.Str == "" || !ascii(value.Str) {
						err = fmt.Errorf("malformed legacy error")
					}
				} else {
					typ, _ := value.Get("type")
					if value.Kind != core.KindObject || typ.Kind != core.KindString || !checks.IsAbsoluteURI(typ.Str) {
						err = fmt.Errorf("malformed error object")
					}
				}
			}
		}
	}
	obs := []core.Observation{}
	for _, w := range wants {
		pass, e := check(out, md, cm, w)
		if err != nil {
			e = err
		}
		v := core.Pass
		if errors.Is(e, errAbsentMetadata) {
			v = core.NotApplicable
		} else if e != nil {
			v = core.Error
		} else if !pass {
			v = core.Fail
		}
		for _, id := range w.Statements {
			detail := "Clause-specific native fixture or inspector-owned loopback TLS observation only. This check does not establish general document equality, full algorithm conformance or deployed authority."
			if w.Check == "http-native-equality" {
				detail = "All captured content and both metadata structures compared with a separate actual native call on the same fixed public record. Map and known DID set ordering are ignored; unknown extension lists retain order. Selected default representations only; general algorithm conformance, error serialization equality and deployed authority are unestablished."
			}
			if e != nil {
				detail = e.Error()
			}
			obs = append(obs, core.Observation{Statement: id, Verdict: v, Input: input, Expected: fmt.Sprintf("%s: %v", w.Check, w.Value), Observed: string(raw), Detail: detail})
		}
	}
	return obs
}
func errorName(md core.DocumentJSON) string {
	v, ok := md.Get("error")
	if !ok {
		return ""
	}
	if v.Kind == core.KindString {
		return v.Str
	}
	t, _ := v.Get("type")
	return t.Str
}
func check(o Result, md, cm core.DocumentJSON, w expected) (bool, error) {
	want, _ := w.Value.(string)
	switch w.Check {
	case "version-ascii", "resolution-media-type", "content-type-ascii", "legacy-keyword", "prefixed-error", "dereference-media-type":
		return checkMetadata(o, md, cm, w)
	case "http-native-equality":
		return checkHTTPNative(o, w)
	case "success":
		d, e := parse(o.Snapshot)
		id, _ := d.Get("id")
		return e == nil && id.Kind == core.KindString && id.Str == o.ReturnedID && checks.IsDID(id.Str) && o.HasContent && errorName(md) == "", nil
	case "id":
		return o.HasContent && errorName(md) == "" && o.ReturnedID == want, nil
	case "fragment":
		return o.HasContent && errorName(md) == "" && o.ReturnedID == want && o.ContentKind == "verification-method", nil
	case "metadata-structure":
		return o.HasContent && errorName(md) == "", nil
	case "no-content-type":
		_, present := md.Get("contentType")
		return !present, nil
	case "representation":
		v, _ := md.Get("contentType")
		d, e := parse(o.Raw)
		id, _ := d.Get("id")
		return e == nil && o.HasContent && errorName(md) == "" && v.Str == want && id.Kind == core.KindString && checks.IsDID(id.Str), nil
	case "error":
		got := errorName(md)
		if want != "notFound" && want != "internalError" {
			want = "https://www.w3.org/ns/did#" + want
		}
		return got == want, nil
	case "failed-no-content":
		return !o.HasContent, nil
	case "failed-empty-metadata":
		return cm.Len() == 0, nil
	case "raised-error":
		return errorName(md) != "", nil
	case "stream-object":
		d, e := parse(o.Raw)
		id, _ := d.Get("id")
		return e == nil && id.Kind == core.KindString && checks.IsDID(id.Str), nil
	case "content-type":
		v, _ := md.Get("contentType")
		return v.Kind == core.KindString && v.Str == want, nil
	case "deactivated":
		v, _ := cm.Get("deactivated")
		return v.Kind == core.KindBool && v.Bool, nil
	case "tls", "status", "resolution-form", "dereference-form", "body-id", "problem":
		return checkHTTP(o, w)
	}
	return false, fmt.Errorf("unknown observation check %q", w.Check)
}
func checkHTTP(o Result, w expected) (bool, error) {
	if o.Exchange == nil {
		return false, fmt.Errorf("missing raw HTTP exchange")
	}
	ex := *o.Exchange
	switch w.Check {
	case "tls":
		return ex.TLS && len(ex.URL) > 8 && ex.URL[:8] == "https://", nil
	case "status":
		v, ok := w.Value.(float64)
		if !ok || ex.Status != int(v) {
			return false, nil
		}
		if ex.Status >= 400 && ex.Status != 410 {
			_, kind, e := checks.BindingError(ex)
			code, present := checks.BindingStatus[kind]
			return e == nil && present && code == ex.Status, nil
		}
		if ex.Status == 410 {
			r, e := checks.ParseResolutionResult(ex.Body)
			d, _ := r.ContentMetadata.Get("deactivated")
			return e == nil && d.Kind == core.KindBool && d.Bool, nil
		}
		return true, nil
	case "resolution-form":
		_, e := parse(ex.Body)
		if e != nil {
			return false, nil
		}
		r, e := checks.ParseResolutionResult(ex.Body)
		if e != nil || checks.MediaTypeEssence(ex.Header.Get("Content-Type")) != checks.MediaTypeDIDResolution {
			return false, nil
		}
		if ex.Status == 410 {
			d, _ := r.ContentMetadata.Get("deactivated")
			return r.Content.Kind == core.KindNull && d.Kind == core.KindBool && d.Bool, nil
		}
		id, _ := r.Content.Get("id")
		want, _ := w.Value.(string)
		_, errorPresent := r.Metadata.Get("error")
		return !errorPresent && r.Content.Kind == core.KindObject && id.Kind == core.KindString && id.Str == want, nil
	case "dereference-form":
		_, e := parse(ex.Body)
		if e != nil {
			return false, nil
		}
		r, e := checks.ParseDereferencingResult(ex.Body)
		id, _ := r.Content.Get("id")
		want, _ := w.Value.(string)
		return e == nil && checks.MediaTypeEssence(ex.Header.Get("Content-Type")) == checks.MediaTypeDIDURLDereferencing && id.Str == want, nil
	case "body-id":
		d, e := parse(ex.Body)
		id, _ := d.Get("id")
		want, _ := w.Value.(string)
		return e == nil && id.Str == want && checks.MediaTypeEssence(ex.Header.Get("Content-Type")) == "application/did", nil
	case "problem":
		d, e := parse(ex.Body)
		t, _ := d.Get("type")
		return e == nil && checks.MediaTypeEssence(ex.Header.Get("Content-Type")) == checks.MediaTypeProblem && t.Kind == core.KindString && checks.IsAbsoluteURI(t.Str), nil
	}
	return false, fmt.Errorf("unknown HTTP check")
}

func ascii(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
