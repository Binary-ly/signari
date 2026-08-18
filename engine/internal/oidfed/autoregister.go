package oidfed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Automatic Registration, OpenID Federation 1.0 §12.1.
//
// An RP in the same federation uses this OP with no prior registration step: its
// Entity Identifier IS its client_id, and everything the OP needs -- redirect
// URIs, keys, permitted algorithms -- comes from metadata resolved through a
// Trust Chain rather than from a registration request.
//
// # What makes it safe, and it is not the chain alone
//
// §12.1: "Since there is no registration step prior to the Authentication
// Request, asymmetric cryptography MUST be used to authenticate requests when
// using Automatic Registration... the OP neither assigns a Client Secret to the
// RP nor returns it as a result of the registration process."
//
// And: "Authentication requests MUST demonstrate that the requesting Entity
// controls the Entity's RP keys... Attempted authentication requests that do not
// do so MUST be rejected."
//
// So a resolved chain establishes WHO an entity is; it does not establish that
// the party sending this particular request is that entity. Anybody can read a
// public Entity Configuration and put its identifier in a client_id. The proof
// is a signed request object, verified against the keys the resolved metadata
// publishes -- which is why RegisteredClient carries those keys out, and why
// there is no path here that produces a client without them.

// RegisteredClient is an RP admitted through Automatic Registration.
type RegisteredClient struct {
	// ClientID is the RP's Entity Identifier. §12.1: "the RP employs its Entity
	// Identifier as the Client ID".
	ClientID string
	// RedirectURIs from the resolved metadata, not from any request.
	RedirectURIs []string
	// JWKS is the RP's protocol key set, used to verify its signed request
	// objects. Never the federation entity keys -- §3.1.1 keeps those separate,
	// and using them here would let a key intended to sign statements about the
	// entity also sign requests on its behalf.
	JWKS json.RawMessage
	// ResponseTypes and Scopes as the metadata declares them.
	ResponseTypes []string
	Scopes        []string
	// TrustAnchor the chain terminated at, and when that chain expires.
	TrustAnchor string
	Expiry      time.Time
}

// Register resolves an RP's Entity Identifier and returns what is needed to
// serve it.
//
// clientID is the RP's Entity Identifier, taken from an authentication request.
// It is attacker-supplied: anybody may put any identifier there, which is why
// nothing about the returned client comes from the request itself.
func Register(ctx context.Context, r *Resolver, clientID string, now time.Time) (*RegisteredClient, error) {
	res, chain, err := r.resolveWithChain(ctx, clientID, now)
	if err != nil {
		return nil, err
	}

	md, err := MetadataOf(chain, TypeRelyingParty)
	if err != nil {
		return nil, err
	}

	out := &RegisteredClient{
		ClientID:    res.Subject,
		TrustAnchor: res.TrustAnchor,
		Expiry:      res.Expiry,
	}
	out.RedirectURIs = stringsFrom(md["redirect_uris"])
	out.ResponseTypes = stringsFrom(md["response_types"])
	out.Scopes = splitSpace(md["scope"])

	if raw, ok := md["jwks"]; ok {
		if b, err := json.Marshal(raw); err == nil {
			out.JWKS = b
		}
	}

	// Both of these are refusals rather than defaults.
	//
	// An RP with no redirect URIs in its metadata cannot be sent an
	// authorization response, and inventing one is how an open redirector gets
	// built. An RP with no keys cannot prove it sent the request, and §12.1
	// makes that proof mandatory -- so admitting it would produce a client that
	// anybody could impersonate by knowing its public identifier.
	if len(out.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%s publishes no redirect_uris in its %s metadata",
			res.Subject, TypeRelyingParty)
	}
	if len(out.JWKS) == 0 {
		return nil, fmt.Errorf("%s publishes no jwks in its %s metadata, so it "+
			"cannot demonstrate control of its keys -- which section 12.1 makes a "+
			"requirement for automatic registration, not an option",
			res.Subject, TypeRelyingParty)
	}
	return out, nil
}

func stringsFrom(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitSpace(v any) []string {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return strings.Fields(s)
}
