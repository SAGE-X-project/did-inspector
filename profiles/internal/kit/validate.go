package kit

import (
	"errors"
	"fmt"
)

// ValidateScenarios checks a scenario file: every scenario has a case id,
// a known function, an input and expectations, and every expectation names
// a known check and at least one statement.
func ValidateScenarios(f ScenarioFile) error {
	var errs []error
	for i, sc := range f.Scenarios {
		where := fmt.Sprintf("scenario %d (%s)", i, sc.Case)
		if sc.Case == "" || sc.Input == "" || len(sc.Expect) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs case, input and expect", where))
		}
		if _, ok := FunctionCapability(sc.Function); !ok {
			errs = append(errs, fmt.Errorf("%s: unknown function %q", where, sc.Function))
		}
		for _, e := range sc.Expect {
			if _, ok := Checks[e.Check]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown check %q", where, e.Check))
			}
			if len(e.Statements) == 0 {
				errs = append(errs, fmt.Errorf("%s: check %s names no statement", where, e.Check))
			}
			if needsValue[e.Check] && len(e.Value) == 0 {
				errs = append(errs, fmt.Errorf("%s: check %s needs a value", where, e.Check))
			}
		}
	}
	for i, p := range f.Probes {
		if _, ok := FunctionCapability(p.Function); !ok || p.Input == "" {
			errs = append(errs, fmt.Errorf("probe %d: needs a known function and an input", i))
		}
	}
	return errors.Join(errs...)
}

var needsValue = map[string]bool{
	"errorCode": true, "documentId": true, "documentHas": true, "documentEquals": true,
	"serviceIds": true, "deactivated": true, "contentMetadataHas": true, "contentType": true,
	"contentTypeAnywhere": true, "uriList": true, "successOrErrorCode": true, "resourceEquals": true,
}

// ValidateDocs checks a document file: every group has a case id, judges
// at least one capability with statements, and has fixtures each capability
// it judges can use.
func ValidateDocs(f DocFile) error {
	var errs []error
	for i, g := range f.Groups {
		where := fmt.Sprintf("group %d (%s)", i, g.Case)
		if g.Case == "" || len(g.Judges) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs case and judges", where))
		}
		for kind, sts := range g.Judges {
			if kind != JudgeConsumer && kind != JudgeProducer && kind != JudgeValidator {
				errs = append(errs, fmt.Errorf("%s: unknown capability %q", where, kind))
			}
			if len(sts) == 0 {
				errs = append(errs, fmt.Errorf("%s: %s judges no statement", where, kind))
			}
			if kind != JudgeConsumer && countDocs(g) == 0 {
				errs = append(errs, fmt.Errorf("%s: %s has no document fixture", where, kind))
			}
		}
		for _, fx := range append(append([]DocFixture{}, g.Valid...), g.Invalid...) {
			if fx.Name == "" {
				errs = append(errs, fmt.Errorf("%s: fixture without name", where))
			}
		}
		for _, fx := range g.Invalid {
			if fx.Why == "" {
				errs = append(errs, fmt.Errorf("%s: invalid fixture %s has no why", where, fx.Name))
			}
		}
	}
	return errors.Join(errs...)
}

func countDocs(g DocGroup) int {
	n := 0
	for _, fx := range append(append([]DocFixture{}, g.Valid...), g.Invalid...) {
		if _, ok := fx.Doc(); ok {
			n++
		}
	}
	return n
}

// ValidateSyntax checks a syntax file: every group has a case id, a known
// kind, statements and items, and every invalid item says why.
func ValidateSyntax(f SyntaxFile) error {
	var errs []error
	for i, g := range f.Groups {
		where := fmt.Sprintf("group %d (%s)", i, g.Case)
		if g.Case == "" || len(g.Statements) == 0 || len(g.Items) == 0 {
			errs = append(errs, fmt.Errorf("%s: needs case, statements and items", where))
		}
		if g.Kind != "did" && g.Kind != "did-url" {
			errs = append(errs, fmt.Errorf("%s: unknown kind %q", where, g.Kind))
		}
		for _, it := range g.Items {
			if !it.Valid && it.Why == "" {
				errs = append(errs, fmt.Errorf("%s: invalid item %q has no why", where, it.Input))
			}
		}
	}
	return errors.Join(errs...)
}
