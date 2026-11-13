package oid4vp

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// An issuer believed by its metadata: its keys are the ones it publishes in its JWT VC
// Issuer Metadata (SD-JWT VC section 3, specs/sdjwtvc.txt:1125-1251), the first of the
// two mechanisms section 2.5 defines (:1085-1089), read for each presentation and kept for
// none of them. Which issuers are believed this way is the operator's choice; an iss
// nobody named is never looked up.

const metadataWellKnown = "/.well-known/jwt-vc-issuer"

// IssuerMetadataURL is where iss publishes its metadata: the well-known string between
// the host and the path, any terminating slash removed first (:1132-1135, :1153-1155).
// iss has to be "a case-sensitive URL using the HTTPS scheme ... but no query or fragment
// components" (:1136-1138).
func IssuerMetadataURL(iss string) (string, error) {
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(iss, "#") {
		return "", fmt.Errorf("the issuer %q is not an https URL without a query or fragment, so it publishes no metadata", iss)
	}
	return "https://" + u.Host + metadataWellKnown + strings.TrimSuffix(u.EscapedPath(), "/"), nil
}

// issuerKeysFromMetadata reads iss's metadata and the keys it names. Every failure
// refuses: "If a recipient cannot validate that the public verification key corresponds
// to the Issuer ... the SD-JWT VC MUST be rejected" (:1107-1110).
func issuerKeysFromMetadata(iss string, fetch Fetcher) (*jose.JSONWebKeySet, error) {
	if fetch == nil {
		return nil, fmt.Errorf("the issuer %s is believed by its metadata and this verifier has no way to read it", iss)
	}
	where, err := IssuerMetadataURL(iss)
	if err != nil {
		return nil, err
	}
	body, contentType, err := fetch(where, "application/json")
	if err != nil {
		return nil, fmt.Errorf("the issuer's metadata could not be read: %w", err)
	}
	// "return the JWT VC Issuer Metadata configuration using the application/json
	// content type" (:1168-1170).
	if mt, _, err := mime.ParseMediaType(contentType); err != nil || mt != "application/json" {
		return nil, fmt.Errorf("the issuer's metadata came as %q, not application/json", contentType)
	}
	var md struct {
		Issuer  string          `json:"issuer"`
		JWKSURI string          `json:"jwks_uri"`
		JWKS    json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, fmt.Errorf("the issuer's metadata is not a JSON object: %w", err)
	}
	// "The issuer value returned MUST be identical to the iss value ... If these values
	// are not identical, the data contained in the response MUST NOT be used" (:1249-1251).
	if md.Issuer != iss {
		return nil, fmt.Errorf("the metadata at %s is for %q, not %q", where, md.Issuer, iss)
	}
	set := len(md.JWKS) > 0 && string(md.JWKS) != "null"
	var raw []byte
	switch {
	// "MUST include either jwks_uri or jwks ... but not both" (:1194-1195).
	case set && md.JWKSURI != "":
		return nil, fmt.Errorf("the issuer's metadata carries both jwks and jwks_uri")
	case set:
		raw = md.JWKS
	case md.JWKSURI != "":
		u, err := url.Parse(md.JWKSURI)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("the issuer's jwks_uri is not an https address")
		}
		if raw, contentType, err = fetch(md.JWKSURI, "application/jwk-set+json, application/json"); err != nil {
			return nil, fmt.Errorf("the issuer's key set could not be read: %w", err)
		}
		// RFC 7517 section 8.5 registers application/jwk-set+json; a key set
		// served as plain JSON is read as one too.
		if mt, _, err := mime.ParseMediaType(contentType); err != nil ||
			(mt != "application/jwk-set+json" && mt != "application/json") {
			return nil, fmt.Errorf("the issuer's key set came as %q", contentType)
		}
	default:
		return nil, fmt.Errorf("the issuer's metadata carries neither jwks nor jwks_uri")
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("the issuer's key set does not parse: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("the issuer's key set holds no key")
	}
	return &keys, nil
}
