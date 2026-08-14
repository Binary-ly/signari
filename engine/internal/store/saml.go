package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/saml"
)

// ErrSAMLProviderUnknown is returned when no service provider is registered
// under the entity id in a request.
//
// A distinct error because the response differs: an unknown entity id must NOT
// produce a SAML error sent back to whatever URL the request named. That would
// make this endpoint a redirector for any entity id an attacker invents.
var ErrSAMLProviderUnknown = errors.New("no service provider registered with that entity id")

// LoadSAMLProvider fetches a provider and everything needed to answer it.
func LoadSAMLProvider(ctx context.Context, db *pgxpool.Pool, entityID string) (*saml.Provider, error) {
	p := &saml.Provider{}
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, entity_id, display_name, name_id_format,
		       sign_assertions, sign_responses, want_authn_requests_signed,
		       COALESCE(sp_signing_cert,''), lifetime_seconds, enabled
		FROM core.saml_providers
		WHERE entity_id = $1`, entityID).Scan(
		&p.ID, &p.OrgID, &p.EntityID, &p.DisplayName, &p.NameIDFormat,
		&p.SignAssertions, &p.SignResponses, &p.WantAuthnRequestsSigned,
		&p.SPSigningCert, &p.LifetimeSeconds, &p.Enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSAMLProviderUnknown
		}
		return nil, fmt.Errorf("loading the service provider: %w", err)
	}

	rows, err := db.Query(ctx, `
		SELECT url, binding, is_default FROM core.saml_acs_urls
		WHERE provider_id = $1::uuid
		ORDER BY is_default DESC, url`, p.ID)
	if err != nil {
		return nil, fmt.Errorf("loading assertion consumer URLs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a saml.ACSURL
		if err := rows.Scan(&a.URL, &a.Binding, &a.IsDefault); err != nil {
			return nil, err
		}
		p.ACSURLs = append(p.ACSURLs, a)
	}
	return p, rows.Err()
}

// EnsureNameID returns the stable pairwise identifier for a user at a provider,
// creating it on first use.
//
// # Why pairwise
//
// Two service providers holding the same person's identifier can compare notes
// and correlate that person across both. Emitting the email address makes that
// trivial AND breaks when the address changes -- because the SP treats the
// NameID as the account key, so a new value means a new, empty account.
//
// A random per-provider value costs nothing and removes both problems.
func EnsureNameID(ctx context.Context, tx pgx.Tx, providerID, userID, orgID, format string) (string, error) {
	// Transient identifiers are per-session by definition and are never stored.
	if format == "transient" {
		return newOpaqueID()
	}
	if format == "emailAddress" {
		var email string
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`, userID).Scan(&email); err != nil {
			return "", err
		}
		if email == "" {
			return "", fmt.Errorf("this service provider is configured for emailAddress " +
				"NameIDs and the account has no email address")
		}
		return email, nil
	}

	var nameID string
	err := tx.QueryRow(ctx, `
		SELECT name_id FROM core.saml_name_ids
		WHERE provider_id = $1::uuid AND user_id = $2::uuid`, providerID, userID).Scan(&nameID)
	if err == nil {
		return nameID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	nameID, err = newOpaqueID()
	if err != nil {
		return "", err
	}
	// ON CONFLICT with a RETURNING re-read, so two concurrent logins settle on
	// one identifier rather than one of them silently minting a second account
	// at the service provider.
	err = tx.QueryRow(ctx, `
		INSERT INTO core.saml_name_ids (provider_id, user_id, org_id, name_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		ON CONFLICT (provider_id, user_id) DO UPDATE SET name_id = core.saml_name_ids.name_id
		RETURNING name_id`, providerID, userID, orgID, nameID).Scan(&nameID)
	if err != nil {
		return "", fmt.Errorf("allocating a NameID: %w", err)
	}
	return nameID, nil
}

// RecordSAMLParticipant notes that this session reached this provider, so
// single logout can enumerate them later.
func RecordSAMLParticipant(ctx context.Context, tx pgx.Tx, sid, providerID, orgID, sessionIndex, nameID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.saml_session_participants
			(sid, provider_id, org_id, session_index, name_id)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5)
		ON CONFLICT (sid, provider_id) DO NOTHING`,
		sid, providerID, orgID, sessionIndex, nameID)
	return err
}

// MarkSAMLRequestSeen records a request id, refusing a replay.
//
// Returns false if this id has been seen before. Used for signed requests --
// above all LogoutRequests, where gosaml2's GHSA-pcgw-qcv5-h8ch is instructive:
// a captured one stays valid forever otherwise, so anyone who saw it once can
// sign that person out whenever they like.
func MarkSAMLRequestSeen(ctx context.Context, tx pgx.Tx, requestID, orgID, providerID string, ttl time.Duration) (bool, error) {
	var inserted bool
	err := tx.QueryRow(ctx, `
		INSERT INTO core.saml_seen_requests (request_id, org_id, provider_id, expires_at)
		VALUES ($1, $2::uuid, NULLIF($3,'')::uuid, now() + $4::interval)
		ON CONFLICT (request_id) DO NOTHING
		RETURNING true`,
		requestID, orgID, providerID, ttl.String()).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		// No row returned means the conflict fired: seen before.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// newOpaqueID generates a NameID with no structure to read.
func newOpaqueID() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating an identifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SessionAuthContext reports what the user actually did to establish this
// session, so the assertion can state it truthfully.
//
// Read at assertion time rather than carried from login, because a session's
// authentication context can change underneath it -- a step-up raises it, and
// an assertion claiming the old value would understate what happened.
func SessionAuthContext(ctx context.Context, tx pgx.Tx, sid string) (acr string, amr []string, authTime time.Time, err error) {
	err = tx.QueryRow(ctx, `
		SELECT acr, amr, auth_time FROM core.sessions WHERE sid = $1`, sid).
		Scan(&acr, &amr, &authTime)
	if err != nil {
		return "", nil, time.Time{}, fmt.Errorf("reading the session's authentication context: %w", err)
	}
	return acr, amr, authTime, nil
}
