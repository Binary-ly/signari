package oid4vp

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// A credential's status is read from a Token Status List, draft-ietf-oauth-status-list-21
// (specs/token-status-list.txt), the one mechanism SD-JWT VC names (specs/sdjwtvc.txt:565-569).
// SD-JWT VC leaves checking it to the verifier ("SHOULD be checked", :1056-1059). Here a
// credential that names a status is not believed until its list says it is valid,
// because a sign-in with a revoked credential is the thing revocation exists to stop.

// StatusFetcher fetches the Status List Token at uri: the body and the response's
// Content-Type. The caller dials, so the address is held to its outbound rules.
type StatusFetcher func(uri string) (body []byte, contentType string, err error)

const (
	// StatusTokenMedia is what a list in JWT form is asked for and answered as
	// (specs/token-status-list.txt:740, :760), the only form SD-JWT VC allows
	// (specs/sdjwtvc.txt:568-569).
	StatusTokenMedia = "application/statuslist+jwt"
	statusTokenType  = "statuslist+jwt"

	// maxStatusOffset bounds how far into a decompressed list an index may point:
	// 2^24 bytes is 134 million credentials at one bit. A list is read only as far as
	// the one place asked about, so this bounds the work, not the memory.
	maxStatusOffset = 1 << 24
)

// The status values (specs/token-status-list.txt:716-720). Only VALID admits.
const (
	statusValid     = 0x00
	statusInvalid   = 0x01
	statusSuspended = 0x02
)

// statusRef is a credential's place in a list, its §6.2 status_list.
type statusRef struct {
	Index int64
	URI   string
}

// statusReference reads the status claim from the issuer-signed payload, which is
// where SD-JWT VC puts it ("MUST NOT be included in the Disclosures",
// specs/sdjwtvc.txt:527-529, 565). No status is no reference.
func statusReference(payload map[string]any) (*statusRef, error) {
	raw, ok := payload["status"]
	if !ok {
		return nil, nil
	}
	status, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the credential's status is not an object")
	}
	// "MUST specify a JSON Object that contains at least one reference to a status
	// mechanism" (specs/token-status-list.txt:575). A credential whose status is
	// kept somewhere this verifier cannot read cannot be shown not to be revoked.
	list, ok := status["status_list"].(map[string]any)
	if !ok {
		names := make([]string, 0, len(status))
		for k := range status {
			names = append(names, k)
		}
		slices.Sort(names)
		return nil, fmt.Errorf("the credential's status is kept by %v, which this verifier does not read, so it cannot be shown not to be revoked", names)
	}
	// idx and uri are both required (:579-581).
	n, ok := list["idx"].(json.Number)
	if !ok {
		return nil, fmt.Errorf("the credential's status_list has no idx")
	}
	idx, err := n.Int64()
	if err != nil || idx < 0 {
		return nil, fmt.Errorf("the credential's status_list idx is not a non-negative integer")
	}
	uri, ok := list["uri"].(string)
	if !ok || uri == "" {
		return nil, fmt.Errorf("the credential's status_list has no uri")
	}
	// https: the list is signed, but which credential is being asked about is
	// readable by anybody on the path (specs/token-status-list.txt:1043-1049).
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("the credential's status list is not at an https address")
	}
	return &statusRef{Index: idx, URI: uri}, nil
}

// checkStatus is §8.3 (specs/token-status-list.txt:787-819): fetch the list, hold it
// to the credential's issuer's keys, and read the one place. Every failure refuses,
// since a failed check makes "no statement about the status" (:819).
//
// The list is fetched for every presentation and never kept: a cached VALID would
// let a credential revoked since sign in again (ADR-007).
func checkStatus(ref statusRef, keys *jose.JSONWebKeySet, fetch StatusFetcher, now time.Time) error {
	if fetch == nil {
		return fmt.Errorf("the credential names a status list and this verifier has no way to read it")
	}
	body, contentType, err := fetch(ref.URI)
	if err != nil {
		return fmt.Errorf("the credential's status list could not be read: %w", err)
	}
	// "MUST use the following content-type" (:758-760).
	if mt, _, err := mime.ParseMediaType(contentType); err != nil || mt != StatusTokenMedia {
		return fmt.Errorf("the status list came as %q, not %s", contentType, StatusTokenMedia)
	}
	tok, err := jose.ParseSigned(string(bytes.TrimSpace(body)), Algorithms())
	if err != nil {
		return fmt.Errorf("the status list did not parse: %w", err)
	}
	if len(tok.Signatures) != 1 {
		return fmt.Errorf("a status list carries exactly one signature")
	}
	// "typ: REQUIRED. The JWT type MUST be statuslist+jwt" (:447).
	if typ, _ := tok.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string); typ != statusTokenType {
		return fmt.Errorf("the status list's typ is %q, not %s", typ, statusTokenType)
	}
	// Signed with a key pinned for the credential's own issuer, §11.3's first case
	// (:949-951). A list kept by some other status issuer is not believed: nothing
	// here says which other party may speak for this issuer's credentials.
	verified, err := verifyWith(tok, keys)
	if err != nil {
		return fmt.Errorf("the status list's signature does not verify with the issuer's keys: %w", err)
	}
	var c struct {
		Subject    string          `json:"sub"`
		IssuedAt   json.Number     `json:"iat"`
		Expires    json.Number     `json:"exp"`
		NotBefore  json.Number     `json:"nbf"`
		TTL        json.Number     `json:"ttl"`
		StatusList json.RawMessage `json:"status_list"`
	}
	dec := json.NewDecoder(bytes.NewReader(verified))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("the status list's claims did not parse: %w", err)
	}
	// "The value MUST be equal to that of the uri claim ... of the Referenced Token"
	// (:451, :805), so a list for other credentials cannot answer for this one.
	if c.Subject != ref.URI {
		return fmt.Errorf("the status list is for %q, not %q", c.Subject, ref.URI)
	}
	iat, err := c.IssuedAt.Float64()
	if c.IssuedAt == "" || err != nil {
		return fmt.Errorf("the status list has no iat")
	}
	if issued := time.Unix(int64(iat), 0); issued.After(now.Add(clockSkew)) {
		return fmt.Errorf("the status list is dated %s, in the future", issued.UTC().Format(time.RFC3339))
	}
	// "it MUST be checked if the Status List Token is expired" (:809), and nbf as
	// RFC 7519 has it (:467, :799).
	if c.Expires != "" {
		exp, err := c.Expires.Float64()
		if err != nil {
			return fmt.Errorf("the status list's exp is not a number")
		}
		if at := time.Unix(int64(exp), 0); !now.Before(at.Add(clockSkew)) {
			return fmt.Errorf("the status list expired at %s", at.UTC().Format(time.RFC3339))
		}
	}
	if c.NotBefore != "" {
		nbf, err := c.NotBefore.Float64()
		if err != nil {
			return fmt.Errorf("the status list's nbf is not a number")
		}
		if at := time.Unix(int64(nbf), 0); now.Add(clockSkew).Before(at) {
			return fmt.Errorf("the status list is not valid until %s", at.UTC().Format(time.RFC3339))
		}
	}
	// "MUST be a positive number" (:457); kept by nothing here, but checked as
	// every existing claim must be (:803).
	if c.TTL != "" {
		if ttl, err := c.TTL.Float64(); err != nil || ttl <= 0 {
			return fmt.Errorf("the status list's ttl is not a positive number")
		}
	}
	var list struct {
		Bits *int    `json:"bits"`
		Lst  *string `json:"lst"`
	}
	if len(c.StatusList) == 0 || json.Unmarshal(c.StatusList, &list) != nil || list.Bits == nil || list.Lst == nil {
		return fmt.Errorf("the status list token carries no status_list with bits and lst")
	}
	value, err := statusAt(*list.Lst, *list.Bits, ref.Index)
	if err != nil {
		return err
	}
	switch value {
	case statusValid:
		return nil
	case statusInvalid:
		return fmt.Errorf("the credential has been revoked by its issuer")
	case statusSuspended:
		return fmt.Errorf("the credential is suspended by its issuer")
	default:
		// 0x03 and 0x0C-0x0F are application specific and the rest unassigned
		// (:722): nothing here knows what they mean, so none of them admits.
		return fmt.Errorf("the credential's status is %#02x, which this verifier does not accept", value)
	}
}

// statusAt is the status at index in a §4.2 list: lst is base64url of a ZLIB stream
// (:344, :264), and each status takes bits bits, packed from the least significant
// bit of each byte (:262, and the warning at :935).
func statusAt(lst string, bits int, index int64) (byte, error) {
	if !slices.Contains([]int{1, 2, 4, 8}, bits) {
		return 0, fmt.Errorf("the status list's bits is %d, not 1, 2, 4 or 8", bits)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return 0, fmt.Errorf("the status list's lst is not base64url: %w", err)
	}
	offset := index * int64(bits) / 8
	if offset >= maxStatusOffset {
		return 0, fmt.Errorf("the credential's place in its status list, %d, is beyond what this verifier reads", index)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, fmt.Errorf("the status list is not a ZLIB stream: %w", err)
	}
	defer func() { _ = zr.Close() }()
	// Read up to the one byte and no further: the rest of the list is about other
	// people, and decompressing it would only cost.
	if _, err := io.CopyN(io.Discard, zr, offset); err != nil {
		return 0, outOfBounds(index, err)
	}
	var one [1]byte
	if _, err := io.ReadFull(zr, one[:]); err != nil {
		return 0, outOfBounds(index, err)
	}
	// Both in range with no conversion: index is non-negative, so shift is 0 to 7.
	shift := index * int64(bits) % 8
	mask := byte(0xFF) >> (8 - bits)
	return (one[0] >> shift) & mask, nil
}

// "If the provided index is out of bounds of the Status List ... the Referenced Token
// MUST be rejected" (:815).
func outOfBounds(index int64, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("the credential's place in its status list, %d, is past the list's end", index)
	}
	return fmt.Errorf("the status list did not decompress: %w", err)
}
