package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238's default, which is what a TOTP app computes
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// softPasskey is a passkey held in software, and the browser in front of it: what a
// platform authenticator does, built from the bytes up, so that what the engine
// verifies is what a browser posts and its WebAuthn library treats it as one.
type softPasskey struct {
	id, handle []byte
	key        *ecdsa.PrivateKey
	rpID       string
	origin     string
	count      uint32
}

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

// enrolPasskey signs a person in and registers a new passkey from their account, as
// they would from the account page.
func enrolPasskey(ctx context.Context, hc *http.Client, e *env) (*softPasskey, error) {
	if _, err := signIn(ctx, hc, e); err != nil {
		return nil, err
	}
	options, err := postJSON(ctx, hc, e.cfg.Issuer+"/account/passkeys/begin", []byte("{}"))
	if err != nil {
		return nil, err
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, err
	}
	o := opts.PublicKey
	if o.Challenge == "" || o.RP.ID == "" {
		return nil, fmt.Errorf("the creation options lack a challenge or rp.id; give the instance an RP ID: %s", trim(options))
	}
	handle, err := base64.RawURLEncoding.DecodeString(o.User.ID)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	p := &softPasskey{id: id, handle: handle, key: key, rpID: o.RP.ID, origin: strings.TrimRight(e.cfg.Issuer, "/")}
	body, err := p.attest(o.Challenge)
	if err != nil {
		return nil, err
	}
	if _, err := postJSON(ctx, hc, e.cfg.Issuer+"/account/passkeys/finish?name=bench", body); err != nil {
		return nil, err
	}
	return p, nil
}

// attest is what navigator.credentials.create() posts, with a "none" attestation.
func (p *softPasskey) attest(challenge string) ([]byte, error) {
	x, y := make([]byte, 32), make([]byte, 32)
	p.key.X.FillBytes(x)
	p.key.Y.FillBytes(y)
	// A COSE EC2 key for ES256 (RFC 9052): kty 2, alg -7, crv 1, x, y.
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	cose = append(append(cose, cborBytes(x)...), 0x22)
	cose = append(cose, cborBytes(y)...)

	attested := make([]byte, 16) // an AAGUID of zero, as a software authenticator's is
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(p.id)))
	attested = append(append(attested, p.id...), cose...)
	data := p.authenticatorData(flagUserPresent|flagUserVerified|flagAttested, 0, attested)

	object := []byte{0xa3}
	object = append(append(object, cborText("fmt")...), cborText("none")...)
	object = append(append(object, cborText("attStmt")...), 0xa0)
	object = append(append(object, cborText("authData")...), cborBytes(data)...)

	cdj, err := p.clientData("webauthn.create", challenge)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64(p.id), "rawId": b64(p.id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(cdj), "attestationObject": b64(object),
			"transports": []string{"internal"}},
	})
}

// assert is what navigator.credentials.get() posts. The counter advances as a real
// authenticator's does, or the engine reads the second use as a clone.
func (p *softPasskey) assert(challenge string) ([]byte, error) {
	p.count++
	data := p.authenticatorData(flagUserPresent|flagUserVerified, p.count, nil)
	cdj, err := p.clientData("webauthn.get", challenge)
	if err != nil {
		return nil, err
	}
	cdh := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte(nil), data...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64(p.id), "rawId": b64(p.id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(cdj), "authenticatorData": b64(data),
			"signature": b64(sig), "userHandle": b64(p.handle)},
	})
}

func (p *softPasskey) authenticatorData(flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(p.rpID))
	out := append(append([]byte(nil), h[:]...), flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func (p *softPasskey) clientData(kind, challenge string) ([]byte, error) {
	return json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": p.origin, "crossOrigin": false})
}

// signIn is a usernameless sign-in from a browser with nothing in it, begin to finish.
func (p *softPasskey) signIn(ctx context.Context, hc *http.Client, e *env) error {
	options, err := postJSON(ctx, hc, e.cfg.Issuer+"/login/passkey/begin", []byte("{}"))
	if err != nil {
		return err
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil || opts.PublicKey.Challenge == "" {
		return fmt.Errorf("no challenge in %s", trim(options))
	}
	body, err := p.assert(opts.PublicKey.Challenge)
	if err != nil {
		return err
	}
	_, err = postJSON(ctx, hc, e.cfg.Issuer+"/login/passkey/finish", body)
	return err
}

func postJSON(ctx context.Context, hc *http.Client, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(hc, req)
}

// The little CBOR (RFC 8949) a "none" attestation is made of.
func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cborText(s string) []byte  { return append(cborHead(3, len(s)), s...) }

// totpCode is what an authenticator app shows now: RFC 6238 with its defaults, thirty
// seconds and six digits over HMAC-SHA-1.
func totpCode(seed string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(seed), "="))
	if err != nil {
		return "", fmt.Errorf("the TOTP seed is not base32: %w", err)
	}
	return hotpCode(key, uint64(at.Unix()/30)), nil
}

func hotpCode(key []byte, counter uint64) string {
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	at := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[at:at+4])&0x7fffffff%1000000)
}
