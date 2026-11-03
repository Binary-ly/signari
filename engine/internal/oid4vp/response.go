package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// An encrypted answer, direct_post.jwt (specs/oid4vp.txt:1568-1592): the wallet posts
// `response`, "an unsigned, encrypted JWT" (:1452) to a key the request named, whose
// payload holds the response parameters "as top-level JSON members" (:1461).
//
// ECDH-ES with A128GCM and nothing else. A128GCM is the default when the request names
// no other (:1459), and this verifier names none, so a different enc is a wallet that
// did not read the request.

// encryptionAlgorithm is the alg the response key is published with, which the JWE's
// alg "MUST be equal to" (:1456-1457).
const encryptionAlgorithm = jose.ECDH_ES

// NewResponseKey makes the key one request's answer is encrypted to: P-256 for
// ECDH-ES, named kid so the answer says which it was encrypted to (:1458). It
// answers the key as PKCS #8, for sealing, and the public JWK the request carries.
func NewResponseKey(kid string) (pkcs8 []byte, public *jose.JSONWebKey, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if pkcs8, err = x509.MarshalPKCS8PrivateKey(k); err != nil {
		return nil, nil, err
	}
	return pkcs8, ResponseJWK(&k.PublicKey, kid), nil
}

// ResponseJWK is the public half as client_metadata's jwks names it: alg present, as
// :1456 requires, use enc, and the kid.
func ResponseJWK(pub *ecdsa.PublicKey, kid string) *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(encryptionAlgorithm), Use: "enc"}
}

// ParseResponseKey reads a key NewResponseKey made.
func ParseResponseKey(pkcs8 []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("a response key is P-256, and this is a %T", k)
	}
	return ec, nil
}

// ParseResponse reads an encrypted answer's header, whose kid says which request's key
// opens it.
func ParseResponse(jwe string) (*jose.JSONWebEncryption, error) {
	obj, err := jose.ParseEncrypted(jwe, []jose.KeyAlgorithm{encryptionAlgorithm},
		[]jose.ContentEncryption{jose.A128GCM})
	if err != nil {
		return nil, fmt.Errorf("the response is not a JWE this verifier asked for: %w", err)
	}
	if obj.Header.KeyID == "" {
		return nil, fmt.Errorf("the response does not say which key it was encrypted to")
	}
	return obj, nil
}

// OpenResponse decrypts an answer with the request's key, and answers its vp_token, as
// the JSON Verify reads, and its state, which must be the request's.
func OpenResponse(obj *jose.JSONWebEncryption, key *ecdsa.PrivateKey, kid, state string) (string, error) {
	if obj.Header.KeyID != kid {
		return "", fmt.Errorf("the response was encrypted to %q, not to this request's key", obj.Header.KeyID)
	}
	plain, err := obj.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("the response does not decrypt with this request's key: %w", err)
	}
	var p struct {
		VPToken json.RawMessage `json:"vp_token"`
		State   *string         `json:"state"`
	}
	if err := json.Unmarshal(plain, &p); err != nil {
		return "", fmt.Errorf("the decrypted response is not a JSON object: %w", err)
	}
	if p.State == nil || *p.State != state {
		return "", fmt.Errorf("the decrypted response is for another request")
	}
	if len(p.VPToken) == 0 {
		return "", fmt.Errorf("the decrypted response holds no vp_token")
	}
	return string(p.VPToken), nil
}
