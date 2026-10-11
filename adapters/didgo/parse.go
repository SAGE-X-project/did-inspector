package didgo

import (
	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/did"
)

// ParseDID parses s with did.Parse and reports the components did-go
// returned.
func (s *Subject) ParseDID(in string) (core.DIDParts, error) {
	d, err := did.Parse(in)
	if err != nil {
		return core.DIDParts{}, err
	}
	return didParts(d), nil
}

// ParseDIDURL parses s as an absolute DID URL with did.ParseURL and reports
// the components did-go returned.
func (s *Subject) ParseDIDURL(in string) (core.DIDURLParts, error) {
	u, err := did.ParseURL(in)
	if err != nil {
		return core.DIDURLParts{}, err
	}
	return core.DIDURLParts{
		DIDURL:      u.String(),
		DID:         didParts(u.DID()),
		Path:        u.Path(),
		Query:       u.Query(),
		HasQuery:    u.HasQuery(),
		Fragment:    u.Fragment(),
		HasFragment: u.HasFragment(),
	}, nil
}

func didParts(d did.DID) core.DIDParts {
	return core.DIDParts{DID: d.String(), Method: d.Method(), MethodSpecificID: d.MSID()}
}
