package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrRefreshReused means the refresh token had already been rotated away. The
// caller MUST revoke the entire family: either the token leaked or the client is
// broken, and rotation without reuse detection is just churn.
var ErrRefreshReused = errors.New("refresh token has already been used")

// ErrRefreshInvalid means unknown, expired, or belonging to a revoked family.
var ErrRefreshInvalid = errors.New("refresh token is invalid")

// RefreshGrant is what a successful rotation yields.
type RefreshGrant struct {
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID string
	OrgID     string
	Scopes    []string
	Resources []string
	// Details is the RFC 9396 grant carried by the whole lineage. On the family
	// rather than the token, because it describes the AUTHORIZATION -- every
	// rotation must inherit the same permission or the grant changes shape as it
	// ages.
	Details []byte
	// DPoPJKT is the JWK Thumbprint this lineage is bound to, empty when the
	// family was established without a DPoP proof. RFC 9449 §5 requires the
	// binding to be VALIDATED at every rotation, not merely recorded at issuance.
	DPoPJKT string
	// CertThumbprint is the RFC 8705 §4 equivalent: the client certificate this
	// lineage is bound to, empty when it was not established over one.
	CertThumbprint string
}

// NewRefreshFamily starts a lineage for one (client, user, session).
//
// The family is the unit of revocation. Revoking only the replayed token would
// leave the thief's successor working, which is the whole reason rotation exists.
func NewRefreshFamily(ctx context.Context, tx pgx.Tx, orgID, clientID, userID, sid string,
	details []byte, dpopJKT, certThumb string) (string, error) {
	// A family with no session has no absolute expiration, so it is refused.
	//
	// OWASP ASVS 5.0 V10.4.8: "Verify that refresh tokens have an absolute
	// expiration, including if sliding refresh token expiration is applied."
	//
	// Ours is satisfied indirectly and the chain is worth stating, because every
	// link is load-bearing. RotateRefreshToken requires one of two deadlines to
	// be ahead, and both are fixed when the authorization is given: the family's
	// own `offline_not_after`, set below and never moved, or the session's
	// `not_after`, which may move with use but which a CHECK holds inside
	// `absolute_not_after`, fixed at sign-in (migration 0180). Rotation issues a
	// new token but can move neither. So a lineage cannot outlive the
	// authorization that started it, however many times it rotates -- which is
	// a stronger bound than a cap on the credential, because it expires the
	// AUTHORIZATION rather than the token that represents it.
	//
	// A family must name its session even when it is offline: the offline
	// deadline is computed from it, and a refresh checks the client's floor
	// against how that session signed in. This refuses one without, rather than
	// relying on no caller passing one.
	if sid == "" {
		return "", fmt.Errorf("a refresh token family must name the session that " +
			"authorized it: its deadlines are what give the lineage an absolute expiration")
	}
	// Offline (5.10): every family is started by a grant of offline_access, and
	// lasts the organisation's offline lifetime from now, whatever its session
	// does -- unless that lifetime is 0, or the session is an impersonation,
	// whose support access must end with the episode. Fixed here and never
	// moved, so an offline lineage has its own absolute expiration.
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.refresh_token_families (org_id, client_id, user_id, sid,
		                                         authorization_details, dpop_jkt,
		                                         cert_thumbprint, offline_not_after)
		SELECT o.id, $2, $3, s.sid, $5, NULLIF($6,''), NULLIF($7,''),
		       CASE WHEN o.offline_lifetime_s > 0 AND s.impersonator_id IS NULL
		            THEN now() + make_interval(secs => o.offline_lifetime_s) END
		  FROM core.organizations o, core.sessions s
		 WHERE o.id = $1::uuid AND s.sid = $4
		RETURNING id::text`,
		orgID, clientID, userID, sid, details, dpopJKT, certThumb).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("creating refresh family: %w", err)
	}
	return id, nil
}

// IssueRefreshToken stores a token in a family. Only the hash is persisted.
func IssueRefreshToken(ctx context.Context, tx pgx.Tx, familyID string, hash []byte,
	scopes, resources []string, ttl time.Duration) error {

	if resources == nil {
		resources = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.refresh_tokens (token_hash, family_id, scopes, resources, expires_at)
		VALUES ($1,$2,$3,$4, now() + $5::interval)`,
		hash, familyID, scopes, resources, ttl.String())
	if err != nil {
		return fmt.Errorf("issuing refresh token: %w", err)
	}
	return nil
}

// RotateRefreshToken atomically consumes a refresh token and returns its grant.
//
// Same technique as authorization codes: the single-use guarantee lives in the
// WHERE clause, so two concurrent refreshes cannot both succeed. It additionally
// joins the family and the session, because a refresh token must stop working the
// moment its family is revoked, its session ends, or its user is deactivated --
// none of which touch the token row itself.
func RotateRefreshToken(ctx context.Context, tx pgx.Tx, hash []byte) (*RefreshGrant, error) {
	var g RefreshGrant
	err := tx.QueryRow(ctx, `
		UPDATE core.refresh_tokens rt
		SET consumed_at = now()
		FROM core.refresh_token_families f
		JOIN core.users u ON u.id = f.user_id
		LEFT JOIN core.sessions s ON s.sid = f.sid
		WHERE rt.token_hash = $1
		  AND rt.consumed_at IS NULL
		  AND rt.expires_at  > now()
		  AND rt.family_id   = f.id
		  AND f.revoked_at IS NULL
		  AND u.status = 'active'
		  AND `+OrgInService("f.org_id")+`
		  -- An offline grant within its own lifetime, or one bound to a session
		  -- that is still live (5.10).
		  AND (f.offline_not_after > now() OR (s.revoked_at IS NULL AND s.not_after > now()))
		RETURNING f.id::text, f.client_id, f.user_id::text,
		          COALESCE(f.sid, ''), f.org_id::text, rt.scopes, rt.resources,
		          f.authorization_details, COALESCE(f.dpop_jkt, ''),
		          COALESCE(f.cert_thumbprint, '')`, hash).
		Scan(&g.FamilyID, &g.ClientID, &g.UserID, &g.SessionID, &g.OrgID, &g.Scopes,
			&g.Resources, &g.Details, &g.DPoPJKT, &g.CertThumbprint)

	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "already rotated" from every other failure. Only reuse
		// warrants destroying the lineage; an expired token is just expired.
		var consumed bool
		e := tx.QueryRow(ctx,
			`SELECT consumed_at IS NOT NULL FROM core.refresh_tokens WHERE token_hash = $1`, hash).
			Scan(&consumed)
		if e == nil && consumed {
			return nil, ErrRefreshReused
		}
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("rotating refresh token: %w", err)
	}
	return &g, nil
}

// LinkSuccessor records which token replaced another, so an audit can walk a
// lineage after the fact and see exactly where a replay entered it. sealed is the
// successor for a client with a retry grace (SealSuccessor), nil for any other.
func LinkSuccessor(ctx context.Context, tx pgx.Tx, oldHash, newHash, sealed []byte) error {
	_, err := tx.Exec(ctx, `UPDATE core.refresh_tokens SET successor_hash = $2, successor_sealed = $3
		WHERE token_hash = $1`, oldHash, newHash, sealed)
	return err
}

// successorContext separates this key from anything else derived from a token.
const successorContext = "signari refresh token successor"

// successorCipher is the cipher derived from a refresh token. A token is 256 bits of
// random, so nothing stretches it.
func successorCipher(token string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(token), nil, successorContext, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealSuccessor seals a successor under a key only the token it replaced gives, so
// whoever presents that token again can have the same answer, and a read of the row
// gives nobody anything: the row holds the old token's hash, not the old token.
func SealSuccessor(oldToken, successor string) ([]byte, error) {
	aead, err := successorCipher(oldToken)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(successor), nil), nil
}

// OpenSuccessor opens what SealSuccessor sealed.
func OpenSuccessor(oldToken string, sealed []byte) (string, error) {
	aead, err := successorCipher(oldToken)
	if err != nil {
		return "", err
	}
	if len(sealed) < aead.NonceSize() {
		return "", errors.New("a sealed successor too short to hold one")
	}
	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("opening a sealed successor: %w", err)
	}
	return string(plain), nil
}

// RefreshRetry spends a token's one retry: a token already rotated, presented again
// within grace, whose successor has not been used and whose lineage is as live as a
// rotation would demand. It answers ErrRefreshReused for anything else, which is the
// caller's cue to revoke as for any reuse. A successor that has been used was received,
// so the token presented now is not a retry by whoever lost the answer.
func RefreshRetry(ctx context.Context, tx pgx.Tx, hash []byte, grace time.Duration) (*RefreshGrant, []byte, error) {
	var g RefreshGrant
	var sealed []byte
	err := tx.QueryRow(ctx, `
		WITH held AS (SELECT token_hash, successor_sealed FROM core.refresh_tokens
		               WHERE token_hash = $1 FOR UPDATE)
		UPDATE core.refresh_tokens rt
		SET successor_sealed = NULL
		FROM held, core.refresh_token_families f
		JOIN core.users u ON u.id = f.user_id
		LEFT JOIN core.sessions s ON s.sid = f.sid
		WHERE rt.token_hash = held.token_hash
		  AND rt.consumed_at > now() - make_interval(secs => $2)
		  AND held.successor_sealed IS NOT NULL
		  AND rt.family_id   = f.id
		  AND f.revoked_at IS NULL
		  AND u.status = 'active'
		  AND `+OrgInService("f.org_id")+`
		  AND (f.offline_not_after > now() OR (s.revoked_at IS NULL AND s.not_after > now()))
		  AND NOT EXISTS (SELECT 1 FROM core.refresh_tokens used
		                   WHERE used.token_hash = rt.successor_hash AND used.consumed_at IS NOT NULL)
		RETURNING f.id::text, f.client_id, f.user_id::text,
		          COALESCE(f.sid, ''), f.org_id::text, rt.scopes, rt.resources,
		          f.authorization_details, COALESCE(f.dpop_jkt, ''),
		          COALESCE(f.cert_thumbprint, ''), held.successor_sealed`, hash, grace.Seconds()).
		Scan(&g.FamilyID, &g.ClientID, &g.UserID, &g.SessionID, &g.OrgID, &g.Scopes,
			&g.Resources, &g.Details, &g.DPoPJKT, &g.CertThumbprint, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrRefreshReused
	}
	if err != nil {
		return nil, nil, fmt.Errorf("retrying a refresh: %w", err)
	}
	return &g, sealed, nil
}

// DiscardRefreshToken removes a token made and never handed out.
func DiscardRefreshToken(ctx context.Context, tx pgx.Tx, hash []byte) error {
	_, err := tx.Exec(ctx, `DELETE FROM core.refresh_tokens WHERE token_hash = $1`, hash)
	return err
}

// RevokeFamilyByToken kills the entire lineage a token belongs to. Called on
// reuse detection.
func RevokeFamilyByToken(ctx context.Context, tx pgx.Tx, hash []byte, reason string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE core.refresh_token_families f
		SET revoked_at = now(), revocation_reason = $2
		FROM core.refresh_tokens rt
		WHERE rt.token_hash = $1 AND rt.family_id = f.id AND f.revoked_at IS NULL`,
		hash, reason)
	if err != nil {
		return 0, fmt.Errorf("revoking refresh family: %w", err)
	}
	return tag.RowsAffected(), nil
}
