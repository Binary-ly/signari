package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// What a driver of a provider's own sign-in pages is made of: a browser walking pages until
// it is sent back to the application, the forms it posts, and the software authenticator's
// answers in the parts a page's script hands a form, rather than as one JSON body.

// attestParts is navigator.credentials.create()'s clientDataJSON and attestationObject.
func (p *softPasskey) attestParts(challenge string) (cdj, object []byte, err error) {
	x, y := make([]byte, 32), make([]byte, 32)
	p.key.X.FillBytes(x)
	p.key.Y.FillBytes(y)
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	cose = append(append(cose, cborBytes(x)...), 0x22)
	cose = append(cose, cborBytes(y)...)
	attested := make([]byte, 16)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(p.id)))
	attested = append(append(attested, p.id...), cose...)
	data := p.authenticatorData(flagUserPresent|flagUserVerified|flagAttested, 0, attested)
	object = []byte{0xa3}
	object = append(append(object, cborText("fmt")...), cborText("none")...)
	object = append(append(object, cborText("attStmt")...), 0xa0)
	object = append(append(object, cborText("authData")...), cborBytes(data)...)
	cdj, err = p.clientData("webauthn.create", challenge)
	return cdj, object, err
}

// assertParts is navigator.credentials.get()'s clientDataJSON, authenticatorData and
// signature, the counter advanced as a real authenticator's is.
func (p *softPasskey) assertParts(challenge string) (cdj, data, sig []byte, err error) {
	p.count++
	data = p.authenticatorData(flagUserPresent|flagUserVerified, p.count, nil)
	if cdj, err = p.clientData("webauthn.get", challenge); err != nil {
		return nil, nil, nil, err
	}
	cdh := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte(nil), data...), cdh[:]...))
	sig, err = ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	return cdj, data, sig, err
}

func b64raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// walkPages follows a browser through a provider's pages from start until it is sent to
// redirectURI, asking onPage what to post for each page it is shown.
func walkPages(ctx context.Context, hc *http.Client, start *http.Request, redirectURI string,
	onPage func(page string, at *url.URL) (*http.Request, error)) (url.Values, error) {
	next := start
	for hop := 0; hop < 16; hop++ {
		resp, err := hc.Do(next)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		traceHop(hop, next, resp, body)
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc, err := next.URL.Parse(resp.Header.Get("Location"))
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(loc.String(), redirectURI) {
				q := loc.Query()
				if e := q.Get("error"); e != "" {
					return nil, fmt.Errorf("refused: %s %s", e, q.Get("error_description"))
				}
				return q, nil
			}
			if next, err = http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil); err != nil {
				return nil, err
			}
		case resp.StatusCode == http.StatusOK:
			if next, err = onPage(string(body), next.URL); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%s answered %d: %s", next.URL.Path, resp.StatusCode, trim(body))
		}
	}
	return nil, fmt.Errorf("not sent back to %s after sixteen hops", redirectURI)
}

func postFields(ctx context.Context, at *url.URL, action string, fields url.Values) (*http.Request, error) {
	target, err := at.Parse(action)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(fields.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// formWithID parses the form whose id is id, where a page holds more than one.
func formWithID(page, id string) (string, url.Values, bool) {
	at := strings.Index(page, `id="`+id+`"`)
	if at < 0 {
		return "", nil, false
	}
	start := strings.LastIndex(strings.ToLower(page[:at]), "<form")
	if start < 0 {
		return "", nil, false
	}
	return parseForm(page[start:])
}

func (e *env) authorizeRequest(ctx context.Context, clientID string) (*http.Request, error) {
	q := url.Values{"client_id": {clientID}, "redirect_uri": {e.cfg.RedirectURI}, "response_type": {"code"},
		"scope": {e.cfg.Scope}, "state": {randomString(16)}, "nonce": {randomString(16)}}
	return http.NewRequestWithContext(ctx, http.MethodGet, e.md.AuthorizationEndpoint+"?"+q.Encode(), nil)
}
