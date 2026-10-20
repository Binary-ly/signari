package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// virtualAuthenticator is a software FIDO2 authenticator and the browser in
// front of it, for driving the passkey ceremonies end to end.
//
// It answers create() with a "none" attestation and get() with an ES256
// assertion, built from the bytes up -- CBOR attestation object, COSE key,
// authenticator data, client data -- so what reaches the handler is what a
// browser posts, and the library verifies it exactly as it would a real one.
// Every part of a ceremony can be bent before it is signed, which is how the
// negative cases are written: the wrong origin, a missing flag, another key.
type virtualAuthenticator struct {
	origin string
	creds  []*virtualCredential
}

// virtualCredential is one resident credential the authenticator holds.
type virtualCredential struct {
	id     []byte
	key    *ecdsa.PrivateKey
	rpID   string
	handle []byte
	count  uint32
}

// ceremonyParts is everything that goes into one response before it is
// signed. A test changes a field to forge exactly one thing.
type ceremonyParts struct {
	Type      string // webauthn.create or webauthn.get
	Challenge string
	Origin    string
	RPID      string // hashed into the authenticator data
	Flags     byte
	Count     uint32
	Key       *ecdsa.PrivateKey // signs the assertion
	CredID    []byte
	Handle    []byte
	// AAGUID is the model the authenticator claims at registration; zero, as
	// a software authenticator's is, unless a test claims one.
	AAGUID [16]byte
	// Format is the attestation: "none", or "packed" for packed
	// SELF-attestation, signed by the new credential's own key, which proves
	// nothing about the model it names.
	Format string
	// Extensions are the browser's clientExtensionResults, empty unless a test
	// reports one, e.g. credProps.
	Extensions map[string]any
}

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagBE = 0x08 // backup eligible
	flagBS = 0x10 // backed up
	flagAT = 0x40 // attested credential data included
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not base64url: %q: %v", s, err)
	}
	return b
}

func authenticatorData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func clientData(t *testing.T, p ceremonyParts) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type": p.Type, "challenge": p.Challenge, "origin": p.Origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// create answers navigator.credentials.create() for the options the server
// sent, and returns the body the browser would post and the new credential.
func (a *virtualAuthenticator) create(t *testing.T, options []byte, bend ...func(*ceremonyParts)) ([]byte, *virtualCredential) {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatalf("the creation options did not parse: %v\n%s", err, options)
	}
	o := opts.PublicKey
	if o.Challenge == "" || o.RP.ID == "" || o.User.ID == "" {
		t.Fatalf("the creation options lack a challenge, rp.id or user.id: %s", options)
	}
	// What a browser would refuse to do: register a credential this
	// authenticator already holds for the account (InvalidStateError).
	for _, ex := range o.ExcludeCredentials {
		for _, c := range a.creds {
			if b64(c.id) == ex.ID && c.rpID == o.RP.ID {
				t.Fatalf("this authenticator already holds a credential the server excludes; " +
					"a browser would refuse with InvalidStateError, so register from another one")
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	cred := &virtualCredential{id: id, key: key, rpID: o.RP.ID, handle: unb64(t, o.User.ID)}

	p := ceremonyParts{
		Type: "webauthn.create", Challenge: o.Challenge, Origin: a.origin, RPID: o.RP.ID,
		Flags: flagUP | flagUV | flagAT, Count: 0, CredID: id, Format: "none",
	}
	for _, b := range bend {
		b(&p)
	}

	pub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := pub.Bytes() // 0x04 || X || Y
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  1, // P-256
		XCoord: point[1:33],
		YCoord: point[33:],
	})
	if err != nil {
		t.Fatal(err)
	}
	attested := append([]byte(nil), p.AAGUID[:]...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(p.CredID)))
	attested = append(attested, p.CredID...)
	attested = append(attested, cose...)

	data := authenticatorData(p.RPID, p.Flags, p.Count, attested)
	cdj := clientData(t, p)
	stmt := map[string]any{}
	if p.Format == "packed" {
		// WebAuthn §8.2 (specs/webauthn.txt:6484-6489): "If x5c is not
		// present, self attestation is in use", and the relying party verifies
		// "sig is a valid signature over the concatenation of
		// authenticatorData and clientDataHash using the credential public key".
		cdh := sha256.Sum256(cdj)
		digest := sha256.Sum256(append(append([]byte(nil), data...), cdh[:]...))
		sig, serr := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if serr != nil {
			t.Fatal(serr)
		}
		stmt = map[string]any{"alg": int64(webauthncose.AlgES256), "sig": sig}
	}
	object, err := webauthncbor.Marshal(map[string]any{
		"fmt": p.Format, "attStmt": stmt, "authData": data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Extensions == nil {
		p.Extensions = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{
		"id": b64(p.CredID), "rawId": b64(p.CredID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  p.Extensions,
		"response": map[string]any{
			"clientDataJSON":    b64(cdj),
			"attestationObject": b64(object),
			"transports":        []string{"internal"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.creds = append(a.creds, cred)
	return body, cred
}

// get answers navigator.credentials.get() with the given credential, and
// returns the body the browser would post. The counter advances as a real
// authenticator's does.
func (a *virtualAuthenticator) get(t *testing.T, options []byte, cred *virtualCredential, bend ...func(*ceremonyParts)) []byte {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			RPID             string `json:"rpId"`
			UserVerification string `json:"userVerification"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatalf("the request options did not parse: %v\n%s", err, options)
	}
	o := opts.PublicKey
	if o.Challenge == "" || o.RPID == "" {
		t.Fatalf("the request options lack a challenge or rpId: %s", options)
	}
	cred.count++
	p := ceremonyParts{
		Type: "webauthn.get", Challenge: o.Challenge, Origin: a.origin, RPID: o.RPID,
		Flags: flagUP | flagUV, Count: cred.count, Key: cred.key,
		CredID: cred.id, Handle: cred.handle,
	}
	for _, b := range bend {
		b(&p)
	}

	data := authenticatorData(p.RPID, p.Flags, p.Count, nil)
	cdj := clientData(t, p)
	cdh := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte(nil), data...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"id": b64(p.CredID), "rawId": b64(p.CredID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64(cdj),
			"authenticatorData": b64(data),
			"signature":         b64(sig),
			"userHandle":        b64(p.Handle),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
