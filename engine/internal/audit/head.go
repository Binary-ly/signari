package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
)

// Signed heads (3.20).
//
// # What was wrong
//
// The chain is a hash chain and nothing more: unkeyed. Anyone who can write
// the table, which the engine's own role can, could change an entry and
// recompute every hash after it, and the chain verified as before. Its own
// comment in checkpoint.go said so.
//
// # What a head is
//
// The newest entry's id and hash, signed with the instance's signing key as a
// JWS and recorded in the chain as an audit.head_signed entry. The private key
// is sealed under the root key, which never lives in the database, so having
// the database is not enough to sign one. A rewrite before a head changes the
// hash the head signed, and verification compares the two.
//
// What it does not stop on its own: deleting every head and then recomputing.
// So heads go where the database cannot reach them: the audit stream sends
// them like any other entry, an export carries the latest, and
// `signari audit verify -head` checks one kept elsewhere against the chain as
// it is now. And `signari doctor` says when heads have stopped appearing.

// HeadEvent is the event a signed head is recorded under.
const HeadEvent = "audit.head_signed"

// HeadType is the JWS typ of a signed head.
const HeadType = "signari-audit-head+jwt"

// headAlgorithms are the signatures a head is accepted with: the engine's
// signing algorithms, never a symmetric one.
var headAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.PS256, jose.EdDSA}

// HeadClaims is what a head signs.
type HeadClaims struct {
	Issuer    string `json:"iss"`
	ThroughID int64  `json:"through_id"`
	EntryHash string `json:"entry_hash"`
	IssuedAt  int64  `json:"iat"`
}

// HeadToSign is the newest entry for a head to cover, or nil when the latest
// head is younger than interval or nothing has been written since it.
func HeadToSign(ctx context.Context, tx pgx.Tx, issuer string, now time.Time,
	interval time.Duration) (*HeadClaims, error) {

	var headID int64
	var headAt time.Time
	err := tx.QueryRow(ctx, `SELECT id, occurred_at FROM core.audit_events WHERE event_type = $1
		ORDER BY id DESC LIMIT 1`, HeadEvent).Scan(&headID, &headAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil && now.Sub(headAt) < interval {
		return nil, nil
	}
	var id int64
	var hash []byte
	err = tx.QueryRow(ctx, `SELECT id, entry_hash FROM core.audit_events ORDER BY id DESC LIMIT 1`).
		Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && id == headID) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &HeadClaims{Issuer: issuer, ThroughID: id, EntryHash: hex.EncodeToString(hash),
		IssuedAt: now.Unix()}, nil
}

// RecordHead writes a signed head into the chain.
func RecordHead(ctx context.Context, tx pgx.Tx, c *HeadClaims, kid, jws string) error {
	return Write(ctx, tx, Event{Type: HeadEvent, Detail: map[string]any{
		"through_id": c.ThroughID,
		"entry_hash": c.EntryHash,
		"kid":        kid,
		"jws":        jws,
	}})
}

// CheckHead verifies a signed head and that the chain still has, at the entry
// it covers, the hash it signed. An entry since archived is reported as such:
// the archive file holds it.
func CheckHead(ctx context.Context, tx pgx.Tx, jws string) (*HeadClaims, error) {
	obj, err := jose.ParseSigned(jws, headAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("the head is not a JWS this engine signs: %w", err)
	}
	if len(obj.Signatures) != 1 {
		return nil, errors.New("the head carries more than one signature")
	}
	h := obj.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != HeadType {
		return nil, fmt.Errorf("the JWS is a %q, not a signed audit head", typ)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT public_jwk::text FROM core.signing_keys WHERE kid = $1`,
		h.KeyID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("the head names key %q, which this deployment has never held", h.KeyID)
		}
		return nil, err
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("key %q: %w", h.KeyID, err)
	}
	payload, err := obj.Verify(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("the head's signature does not verify against key %q", h.KeyID)
	}
	var c HeadClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("the head's claims do not parse: %w", err)
	}
	want, err := hex.DecodeString(c.EntryHash)
	if err != nil {
		return nil, fmt.Errorf("the head's entry hash is not hex")
	}
	var have []byte
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM core.audit_events WHERE id = $1`, c.ThroughID).Scan(&have)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, through, aerr := archiveAnchor(ctx, tx); aerr == nil && c.ThroughID <= through {
			return &c, fmt.Errorf("entry %d, which the head covers, has been archived; check it in the archive file", c.ThroughID)
		}
		return &c, fmt.Errorf("entry %d, which the head covers, is not in the trail", c.ThroughID)
	}
	if err != nil {
		return &c, err
	}
	if !bytes.Equal(have, want) {
		return &c, fmt.Errorf("entry %d does not have the hash the head signed: the trail up to it "+
			"was rewritten after the head was signed at %s", c.ThroughID,
			time.Unix(c.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	return &c, nil
}

// VerifyHeads checks every head the trail holds from entry fromID on. It
// returns how many it checked and the first that fails, by the head entry's
// id, with why.
func VerifyHeads(ctx context.Context, tx pgx.Tx, fromID int64) (checked int, failedAt int64, why string, err error) {
	rows, err := tx.Query(ctx, `SELECT id, detail->>'jws' FROM core.audit_events
		WHERE event_type = $1 AND id >= $2 ORDER BY id`, HeadEvent, fromID)
	if err != nil {
		return 0, 0, "", err
	}
	type head struct {
		id  int64
		jws string
	}
	var heads []head
	for rows.Next() {
		var h head
		if err := rows.Scan(&h.id, &h.jws); err != nil {
			rows.Close()
			return 0, 0, "", err
		}
		heads = append(heads, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, "", err
	}
	_, archived, err := archiveAnchor(ctx, tx)
	if err != nil {
		return 0, 0, "", err
	}
	for _, h := range heads {
		c, cerr := CheckHead(ctx, tx, h.jws)
		if cerr != nil && c != nil && c.ThroughID <= archived {
			continue // the entry it covers is in an archive file
		}
		checked++
		if cerr != nil {
			return checked, h.id, cerr.Error(), nil
		}
	}
	return checked, 0, "", nil
}

// LatestHead is the newest signed head, for an export to carry.
func LatestHead(ctx context.Context, tx pgx.Tx) (jws string, at time.Time, err error) {
	err = tx.QueryRow(ctx, `SELECT detail->>'jws', occurred_at FROM core.audit_events
		WHERE event_type = $1 ORDER BY id DESC LIMIT 1`, HeadEvent).Scan(&jws, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, nil
	}
	return jws, at, err
}

// HeadInterval reads SIGNARI_AUDIT_HEAD_INTERVAL: how often serve signs a head,
// an hour unless set, and at least a minute, the janitor's pace.
func HeadInterval(getenv func(string) string) (time.Duration, error) {
	v := getenv("SIGNARI_AUDIT_HEAD_INTERVAL")
	if v == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute {
		return 0, fmt.Errorf("SIGNARI_AUDIT_HEAD_INTERVAL=%q: want a duration of at least 1m, such as 1h", v)
	}
	return d, nil
}

// HeadAge is how long ago the newest head was signed and how many entries
// have been written since, for doctor; ok is false when there is no head.
func HeadAge(ctx context.Context, tx pgx.Tx, now time.Time) (age time.Duration, since int64, ok bool, err error) {
	var id int64
	var at time.Time
	err = tx.QueryRow(ctx, `SELECT id, occurred_at FROM core.audit_events WHERE event_type = $1
		ORDER BY id DESC LIMIT 1`, HeadEvent).Scan(&id, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT count(*) FROM core.audit_events`).Scan(&since)
		return 0, since, false, err
	}
	if err != nil {
		return 0, 0, false, err
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE id > $1`, id).Scan(&since)
	return now.Sub(at), since, true, err
}
