package did11

import (
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// bindingInvariants are the rules every response of the HTTP(S) binding
// must satisfy (DID Resolution §12.1).
func bindingInvariants() []kit.BindingInvariant {
	return []kit.BindingInvariant{
		{Statement: r("bindings-https.2"), Partial: "judged by the scheme of the endpoint and the connection each response arrived on; the TLS version and configuration are not judged",
			Check: func(o kit.BindingOutcome) (bool, bool, string, string) {
				return true, o.Ex.TLS && kit.EndpointIsHTTPS(o.Endpoint), "a response over TLS from an https endpoint",
					fmt.Sprintf("endpoint scheme https %v, TLS %v", kit.EndpointIsHTTPS(o.Endpoint), o.Ex.TLS)
			}},
		{Statement: r("bindings-https.22"), Partial: "judged on responses whose error type the inspector can read: the error property of a complete result, or a problem details body",
			Check: func(o kit.BindingOutcome) (bool, bool, string, string) {
				_, t, err := checks.BindingError(o.Ex)
				want, inTable := checks.BindingStatus[t]
				if err != nil || !inTable {
					return false, false, "", ""
				}
				return true, o.Ex.Status == want, fmt.Sprintf("status %d for error %s", want, t), fmt.Sprintf("status %d", o.Ex.Status)
			}},
		{Statement: r("bindings-https.24"), Partial: "judged on complete results that report deactivated true",
			Check: func(o kit.BindingOutcome) (bool, bool, string, string) {
				res, err := o.Result()
				if err != nil || o.ContentType() != fullMediaType(o.Request.Function) {
					return false, false, "", ""
				}
				v, _ := res.ContentMetadata.Get("deactivated")
				if v.Kind != core.KindBool || !v.Bool {
					return false, false, "", ""
				}
				return true, o.Ex.Status == 410, "status 410 for a deactivated DID", fmt.Sprintf("status %d", o.Ex.Status)
			}},
		resultFormInvariant(r("bindings-https.27"), checks.MediaTypeDIDResolution, checks.ParseResolutionResult),
		resultFormInvariant(r("bindings-https.34"), checks.MediaTypeDIDURLDereferencing, checks.ParseDereferencingResult),
	}
}

func fullMediaType(fn string) string {
	if fn == kit.FnDereference {
		return checks.MediaTypeDIDURLDereferencing
	}
	return checks.MediaTypeDIDResolution
}

// resultFormInvariant: a response whose Content-Type is the media type of
// a complete result carries one.
func resultFormInvariant(st, mediaType string, parse func([]byte) (checks.BindingResult, error)) kit.BindingInvariant {
	return kit.BindingInvariant{Statement: st, Partial: "judged by the form of the result; that it is the result of the function is judged by the binding scenarios",
		Check: func(o kit.BindingOutcome) (bool, bool, string, string) {
			if o.ContentType() != mediaType {
				return false, false, "", ""
			}
			_, err := parse(o.Ex.Body)
			return true, err == nil, "a body that is a " + mediaType + " result", fmt.Sprintf("%v: %s", err, o.Summary())
		}}
}
