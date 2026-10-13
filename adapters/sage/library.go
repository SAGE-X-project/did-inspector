package sage

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/vm"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

// InspectSyntax archives actual selected library calls. Errors are returned
// unchanged as data; adapter dispatch errors stay separate.
func (*Subject) InspectSyntax(_ context.Context, q sageresolution.SyntaxRequest) (sageresolution.SyntaxResult, error) {
	out := sageresolution.SyntaxResult{Request: q}
	var err error
	switch q.Kind {
	case "did":
		out.Operation = "github.com/sage-x-project/did-go/did.Parse"
		v, e := did.Parse(q.Input)
		out.Value = v.String()
		err = e
	case "url":
		out.Operation = "github.com/sage-x-project/did-go/did.ParseURL"
		v, e := did.ParseURL(q.Input)
		out.Value = v.String()
		err = e
	case "reference":
		out.Operation = "github.com/sage-x-project/did-go/did.ParseReference+DIDURL.Resolve"
		base, e := did.ParseURL(q.Base)
		if e != nil {
			return out, e
		}
		v, e := did.ParseReference(q.Input)
		err = e
		if err == nil {
			v, err = v.Resolve(base)
			out.Value = v.String()
		}
	default:
		return out, errors.New("unknown syntax operation")
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out, nil
}

// InspectCodec selects the actual subject row by name and key role. Neither
// subject statement annotations nor its registry supply expected bytes.
func (*Subject) InspectCodec(_ context.Context, q sageresolution.CodecRequest) (sageresolution.CodecResult, error) {
	out := sageresolution.CodecResult{Operation: "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey", Request: q}
	var selected vm.MultikeyCodec
	found := false
	for _, c := range vm.MultikeyCodecs() {
		if c.Name == q.Name && c.Secret == q.Secret {
			selected = c
			found = true
			break
		}
	}
	if !found {
		return out, errors.New("no selected codec")
	}
	out.Name, out.Prefix, out.Length, out.Secret = selected.Name, append([]byte(nil), selected.Prefix[:]...), selected.KeyLength, selected.Secret
	value, e := vm.EncodeMultikey(selected, q.Key)
	out.Encoded = value
	if e != nil {
		out.EncodeError = e.Error()
	}
	c, raw, e := vm.DecodeMultikey(q.Encoded, q.Secret)
	out.Decoded = append([]byte(nil), raw...)
	if e != nil {
		out.DecodeError = e.Error()
	} else {
		out.DecodeName, out.DecodePrefix, out.DecodeLength, out.DecodeSecret = c.Name, append([]byte(nil), c.Prefix[:]...), c.KeyLength, c.Secret
	}
	return out, nil
}
