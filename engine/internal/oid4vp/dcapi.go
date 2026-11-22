package oid4vp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

// OpenID4VP over the browser's Digital Credentials API (specs/oid4vp.txt:2423-2689): the
// page hands the request to navigator.credentials.get, the browser takes it to a wallet
// with the page's origin, and the wallet's answer comes back to the same page
// (specs/digital-credentials.txt:559-565, :1542-1546), which posts it here. There is no
// response URI, no state and no redirect: the answer is bound to this origin instead of to
// a client identifier (:2663-2664).

// The exchange protocols (:2454-2456; specs/digital-credentials.txt:1627-1631).
const (
	ProtocolUnsigned = "openid4vp-v1-unsigned"
	ProtocolSigned   = "openid4vp-v1-signed"
)

// The response modes over the API: dc_api, or dc_api.jwt for an encrypted answer (:2501).
const (
	ModeDCAPI    = "dc_api"
	ModeDCAPIJWT = "dc_api.jwt"
)

// DCAPIMode is the mode over the API that matches mode over a URL.
func DCAPIMode(mode string) string {
	if mode == ModeDirectPostJWT {
		return ModeDCAPIJWT
	}
	return ModeDCAPI
}

// OriginAudience is what a presentation over the API is made for: "the Origin, prefixed
// with origin:", signed request or not (:2663-2664). The origin is serialized as a browser
// does, scheme, host and any port with no path; the specification's examples add a
// trailing slash (:674, :2663), which an origin does not have, and the normative text
// names the origin.
func OriginAudience(origin string) string { return "origin:" + origin }

// DCAPI is the request as navigator.credentials.get is handed it: the protocol, and the
// data. With key, signed: every parameter in a request object, with the client_id the
// wallet authenticates the verifier by (:2500) and the origins it may be asked from, which
// the wallet holds the browser's origin to (:2505), as JWS Compact Serialization in
// "request" (:2533). Without, unsigned: the parameters as they are, and no client_id
// (:2496). Neither carries a response_uri or a state, which the API has no use for (:2511).
func (r Request) DCAPI(origin string, key crypto.Signer, chain []*x509.Certificate, now time.Time) (
	string, map[string]any, error) {
	p := map[string]any{
		"response_type":   "vp_token",
		"response_mode":   DCAPIMode(r.ResponseMode),
		"nonce":           r.Nonce,
		"dcql_query":      r.Ask.Query(),
		"client_metadata": r.metadata(),
	}
	if key == nil {
		return ProtocolUnsigned, p, nil
	}
	p["client_id"] = r.ClientID
	p["expected_origins"] = []string{origin}
	p["aud"] = staticAudience
	p["iat"] = now.Unix()
	p["exp"] = now.Add(RequestLifetime).Unix()
	signed, err := Sign(p, key, chain)
	if err != nil {
		return "", nil, err
	}
	return ProtocolSigned, map[string]any{"request": signed}, nil
}

// ReadDCAPIAnswer is the vp_token a DigitalCredential's data holds: the response
// parameters as an object, or under dc_api.jwt "response", an encrypted JWT holding them
// (:2649, :2501), opened with key, which kid names. An error from the wallet is an object
// with "error" alone (:2651), reported as refused. key is nil for a request that did
// not ask for encryption; one that did takes nothing in clear but an error (:1574).
func ReadDCAPIAnswer(data []byte, key *ecdsa.PrivateKey, kid string) (vpToken string, refused bool, err error) {
	var a struct {
		VPToken  json.RawMessage `json:"vp_token"`
		Response string          `json:"response"`
		Error    string          `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&a); err != nil {
		return "", false, fmt.Errorf("the wallet's answer is not a JSON object: %w", err)
	}
	switch {
	case a.Error != "":
		return "", true, nil
	case key != nil && a.Response == "":
		return "", false, fmt.Errorf("this request asked for an encrypted answer")
	case key == nil && a.Response != "":
		return "", false, fmt.Errorf("this request did not ask for an encrypted answer")
	case key != nil:
		obj, err := ParseResponse(a.Response)
		if err != nil {
			return "", false, err
		}
		if obj.Header.KeyID != kid {
			return "", false, fmt.Errorf("the answer was encrypted to %q, not to this request's key", obj.Header.KeyID)
		}
		plain, err := obj.Decrypt(key)
		if err != nil {
			return "", false, fmt.Errorf("the answer does not decrypt with this request's key: %w", err)
		}
		var inner struct {
			VPToken json.RawMessage `json:"vp_token"`
		}
		if err := json.Unmarshal(plain, &inner); err != nil || len(inner.VPToken) == 0 {
			return "", false, fmt.Errorf("the decrypted answer holds no vp_token")
		}
		return string(inner.VPToken), false, nil
	case len(a.VPToken) == 0:
		return "", false, fmt.Errorf("the wallet's answer holds no vp_token")
	}
	return string(a.VPToken), false, nil
}
