package oid4vci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"signari.dev/engine/internal/sdjwt"
)

// A W3C Verifiable Credential signed as a JWT, not using JSON-LD: OID4VCI Appendix
// A.1.1, `jwt_vc_json`. The shape follows that appendix's example at
// specs/oid4vci.txt:3404. The VC Data Model it cites is not in specs/.
//
// Nothing here is processed as JSON-LD, as A.1.1.1 requires: `@context` is written
// because the data model asks for it, and never read.

// vcContext is the data model's base context, the one the appendix's example opens
// with.
const vcContext = "https://www.w3.org/2018/credentials/v1"

// VCTypes is what `credential_definition.type` says of a configuration, the base type
// and its own.
func VCTypes(cfg Configuration) []string { return []string{"VerifiableCredential", cfg.VCT} }

// issueJWTVC signs one credential to the holder's key.
//
// The key is bound as a did:jwk in `sub` and `credentialSubject.id`, the way the
// appendix's example does, so a verifier resolves it from the credential alone. There
// is no selective disclosure in this format, which is why a configuration of it may
// not name selective claims.
func (i Issuer) issueJWTVC(cfg Configuration, subject map[string]any, holderKey *jose.JSONWebKey, now time.Time) (string, error) {
	public, err := json.Marshal(holderKey.Public())
	if err != nil {
		return "", fmt.Errorf("encoding the holder's key: %w", err)
	}
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(public)
	id := "urn:uuid:" + uuid.NewString()

	// The same rounding as an SD-JWT VC, for the same reason: credentials of one
	// batch must not be told apart by the second they were signed.
	now = sdjwt.RoundForUnlinkability(now, cfg.Lifetime)

	// A claim the subject does not have is omitted rather than emitted empty. The
	// id goes on last so that no claim of that name can replace it.
	credentialSubject := map[string]any{}
	for _, name := range cfg.AlwaysClaims {
		if v, ok := subject[name]; ok && v != nil && v != "" {
			credentialSubject[name] = v
		}
	}
	credentialSubject["id"] = did

	vc := map[string]any{
		"@context":          []string{vcContext},
		"id":                id,
		"type":              VCTypes(cfg),
		"issuer":            i.CredentialIssuer,
		"issuanceDate":      now.UTC().Format(time.RFC3339),
		"credentialSubject": credentialSubject,
	}
	claims := map[string]any{"iss": i.CredentialIssuer, "sub": did, "jti": id, "nbf": now.Unix(), "vc": vc}
	if cfg.Lifetime > 0 {
		expires := now.Add(cfg.Lifetime)
		claims["exp"] = expires.Unix()
		vc["expirationDate"] = expires.UTC().Format(time.RFC3339)
	}
	if i.Status != nil {
		claims["status"] = i.Status.claim()
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jwt, err := i.Sign(body, "JWT")
	if err != nil {
		return "", fmt.Errorf("signing the credential: %w", err)
	}
	return jwt, nil
}
