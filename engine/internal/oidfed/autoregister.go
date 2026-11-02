package oidfed

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
	// Name is its client_name, or "" when it gives none.
	Name string
	// TrustAnchor the chain terminated at, and when that chain expires.
	TrustAnchor string
	Expiry      time.Time

	chain []Statement
}

// ImmediateSuperior is the entity above this one in its chain.
func (c *RegisteredClient) ImmediateSuperior() string { return c.chain[1].Issuer }

// EntityJWKS is the `jwks` claim of the client's Entity Configuration, which an
// Explicit Registration answer hands back as it came.
func (c *RegisteredClient) EntityJWKS() json.RawMessage { return c.chain[0].JWKS }

// RequireTrustMarks holds a client to a Trust Mark of each type given, valid under §7.3:
// genuinely issued to it, by an issuer the Trust Anchor lets issue that type where it
// says, and with trust in that issuer established first. A mark that fails any of it
// counts for nothing and another of the same type may still do.
func (r *Resolver) RequireTrustMarks(ctx context.Context, c *RegisteredClient, types []string, now time.Time) error {
	if len(types) == 0 {
		return nil
	}
	at := slices.IndexFunc(r.Anchors, func(a TrustAnchor) bool { return a.EntityID == c.TrustAnchor })
	if at < 0 {
		return fmt.Errorf("%s is not an anchor here", c.TrustAnchor)
	}
	// What the anchor says of Trust Marks is in its own configuration, which a chain
	// does not reach: that ends with what it says of the entity below it.
	anchor, err := r.Fetcher.EntityConfigurationOf(ctx, c.TrustAnchor)
	if err != nil {
		return err
	}
	if err := verifyWith(anchor, r.Anchors[at].JWKS); err != nil {
		return fmt.Errorf("the trust anchor's own configuration: %w", err)
	}
	leaf := c.chain[0]
	for _, wanted := range types {
		held := false
		for _, entry := range leaf.TrustMarks {
			if held = entry.Type == wanted && r.trustMarkHolds(ctx, entry, wanted, leaf, anchor, r.Anchors[at].JWKS, now); held {
				break
			}
		}
		if !held {
			return fmt.Errorf("%s holds no valid %s trust mark", c.ClientID, wanted)
		}
	}
	return nil
}

func (r *Resolver) trustMarkHolds(ctx context.Context, entry TrustMarkEntry, wanted string, leaf, anchor Statement,
	anchorKeys json.RawMessage, now time.Time) bool {
	mark, err := ParseTrustMarkUnverified(entry.JWT)
	if err != nil || mark.Type != wanted {
		return false
	}
	if anchor.TrustMarkIssuers.Governs(wanted) {
		if permitted, _ := anchor.TrustMarkIssuers.IssuerPermitted(wanted, mark.Issuer); !permitted {
			return false
		}
	}
	// An anchor is trusted already and has no chain to itself, and may issue marks too.
	keys := anchorKeys
	if mark.Issuer != anchor.Subject {
		_, issuer, err := r.resolveWithChain(ctx, mark.Issuer, now)
		if err != nil {
			return false
		}
		keys = issuer[0].JWKS
	}
	_, err = ValidateTrustMark(entry.JWT, TrustMarkOptions{ContainingEntity: leaf.Subject, IssuerJWKS: keys,
		Owners: anchor.TrustMarkOwners, Now: now})
	return err == nil
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
	return registered(res, chain)
}

// RegisterExplicitly is §12.2: an RP sends its Entity Configuration, perhaps tailored
// to this OP, so what it sent is what is resolved and not what it publishes. Its
// signature is checked by ValidateChain, against the keys its superior attests to:
// §12.2.2 has that happen "After validating at least one Trust Chain", as the keys in
// the statement mean nothing before. entityID is this OP, which it has to be addressed
// to or it could be replayed at another.
func RegisterExplicitly(ctx context.Context, r *Resolver, raw, entityID string, now time.Time) (*RegisteredClient, error) {
	leaf, err := ParseStatement(raw)
	if err != nil {
		return nil, err
	}
	if leaf.Issuer == "" || leaf.Issuer != leaf.Subject {
		return nil, fmt.Errorf("an Explicit Registration request is the RP's own Entity Configuration")
	}
	var one string
	var many []string
	if json.Unmarshal(leaf.Audience, &one) != nil && json.Unmarshal(leaf.Audience, &many) == nil && len(many) == 1 {
		one = many[0]
	}
	if one != entityID {
		return nil, fmt.Errorf("the request's aud is not this entity")
	}
	res, chain, err := r.resolveFrom(ctx, leaf, leaf.Subject, now)
	if err != nil {
		return nil, err
	}
	return registered(res, chain)
}

// registered is what a resolved chain says of a relying party.
func registered(res *ChainResult, chain []Statement) (*RegisteredClient, error) {
	md, err := MetadataOf(chain, TypeRelyingParty)
	if err != nil {
		return nil, err
	}

	out := &RegisteredClient{
		ClientID:    res.Subject,
		TrustAnchor: res.TrustAnchor,
		Expiry:      res.Expiry,
		chain:       chain,
	}
	out.Name, _ = md["client_name"].(string)
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
