package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
)

// ErrSAMLProviderUnknown is returned when no service provider is registered
// under the entity id in a request.
//
// A distinct error because the response differs: an unknown entity id must NOT
// produce a SAML error sent back to whatever URL the request named. That would
// make this endpoint a redirector for any entity id an attacker invents.
var ErrSAMLProviderUnknown = errors.New("no service provider registered with that entity id")

// LoadSAMLProvider fetches a provider at the deployment's endpoints, where an entity id
// is held once, and everything needed to answer it.
func LoadSAMLProvider(ctx context.Context, db *pgxpool.Pool, entityID string) (*saml.Provider, error) {
	return loadSAMLProvider(ctx, db, "entity_id = $1 AND org_endpoint = false", entityID)
}

// LoadOrgSAMLProvider is the same at an organisation's endpoints.
func LoadOrgSAMLProvider(ctx context.Context, db *pgxpool.Pool, orgID, entityID string) (*saml.Provider, error) {
	return loadSAMLProvider(ctx, db, "entity_id = $1 AND org_id = $2::uuid AND org_endpoint", entityID, orgID)
}

// LoadSAMLProviderByID is the same by the provider's own id.
func LoadSAMLProviderByID(ctx context.Context, db *pgxpool.Pool, id string) (*saml.Provider, error) {
	return loadSAMLProvider(ctx, db, "id::text = $1", id)
}

// OrgBySlug finds the organisation a path names in an instance, or
// ErrSAMLProviderUnknown for none, since all a path does is find a provider. An empty
// instance is a server that was not told its own, as for InInstance.
func OrgBySlug(ctx context.Context, q rowQuerier, instanceID, slug string) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM core.organizations
		WHERE slug = $1 AND instance_id = COALESCE(NULLIF($2, '')::uuid, instance_id)`, slug, instanceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSAMLProviderUnknown
	}
	return id, err
}

func loadSAMLProvider(ctx context.Context, db *pgxpool.Pool, where string, args ...any) (*saml.Provider, error) {
	p := &saml.Provider{}
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, entity_id, display_name, name_id_format,
		       sign_assertions, sign_responses, want_authn_requests_signed,
		       COALESCE(sp_signing_cert,''), COALESCE(sp_encryption_cert,''),
		       sp_key_transport, signature_alg, wsfed_saml_version,
		       CASE WHEN org_endpoint THEN (SELECT o.slug FROM core.organizations o WHERE o.id = core.saml_providers.org_id)
		            ELSE '' END,
		       lifetime_seconds, enabled, COALESCE(name_id_attribute, ''),
		       idp_initiated, default_relay_state,
		       (SELECT o.instance_id::text FROM core.organizations o WHERE o.id = core.saml_providers.org_id),
		       EXISTS (SELECT 1 FROM core.access_policies a WHERE a.org_id = core.saml_providers.org_id),
		       EXISTS (SELECT 1 FROM core.providers h
		                WHERE h.org_id = core.saml_providers.org_id AND h.hook = 'saml_assertion'),
		       EXISTS (SELECT 1 FROM core.saml_group_release g WHERE g.provider_id = core.saml_providers.id),
		       attributes <> '{}'::jsonb,
		       COALESCE((SELECT jsonb_agg(jsonb_build_object('URL', u.url, 'Binding', u.binding, 'IsDefault', u.is_default)
		                                  ORDER BY u.is_default DESC, u.url)
		                   FROM core.saml_acs_urls u WHERE u.provider_id = core.saml_providers.id), '[]'::jsonb)
		FROM core.saml_providers
		WHERE `+where, args...).Scan(
		&p.ID, &p.OrgID, &p.EntityID, &p.DisplayName, &p.NameIDFormat,
		&p.SignAssertions, &p.SignResponses, &p.WantAuthnRequestsSigned,
		&p.SPSigningCert, &p.SPEncryptionCert, &p.SPKeyTransport, &p.SignatureAlg, &p.WSFedSAMLVersion, &p.EndpointOrg,
		&p.LifetimeSeconds, &p.Enabled, &p.NameIDAttribute, &p.IdPInitiated, &p.DefaultRelayState,
		&p.InstanceID, &p.HasAccessPolicy, &p.HasAssertionHook, &p.ReleasesGroups, &p.ReleasesAttributes,
		&p.ACSURLs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSAMLProviderUnknown
		}
		return nil, fmt.Errorf("loading the service provider: %w", err)
	}
	return p, nil
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
func EnsureNameID(ctx context.Context, tx claimReader, providerID, userID, orgID, format string) (string, error) {
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
// single logout can enumerate them later, with the NameID and its format as the
// assertion carried them.
func RecordSAMLParticipant(ctx context.Context, tx pgx.Tx, sid, providerID, orgID, sessionIndex, nameID,
	nameIDFormat string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO core.saml_session_participants
			(sid, provider_id, org_id, session_index, name_id, name_id_format)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6)
		ON CONFLICT (sid, provider_id) DO NOTHING`,
		sid, providerID, orgID, sessionIndex, nameID, nameIDFormat)
	return err
}

// SessionHoldsReplyURL reports whether a URL is a reply URL of an application this
// session was given a token for, which is all a WS-Federation sign-out naming no realm
// can be held to.
func SessionHoldsReplyURL(ctx context.Context, q rowQuerier, sid, replyURL string) (bool, error) {
	var held bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM core.saml_session_participants p
		                 JOIN core.saml_acs_urls u ON u.provider_id = p.provider_id
		                WHERE p.sid = $1 AND u.url = $2)`, sid, replyURL).Scan(&held)
	return held, err
}

// NameIDFromAttribute reads a person's NameID from what a provider names. Refused
// rather than falling back: another identifier would be a new, empty account at the
// provider. Refused too when the attribute has since become one a person can edit,
// since whoever writes this value signs in as whoever else holds it there.
func NameIDFromAttribute(ctx context.Context, tx claimReader, userID, orgID, attribute string, root *keys.RootKey) (string, error) {
	if attribute == nameIDFromUsername {
		var username string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(username, '') FROM core.users WHERE id = $1::uuid`,
			userID).Scan(&username); err != nil {
			return "", err
		}
		if username == "" {
			return "", errors.New("this service provider takes its NameID from the username and the account has none")
		}
		return username, nil
	}
	var writable bool
	if err := tx.QueryRow(ctx, `SELECT user_writable FROM core.user_attribute_schema
		WHERE org_id = $1::uuid AND name = $2`, orgID, attribute).Scan(&writable); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("this service provider takes its NameID from %q, which is no longer declared", attribute)
		}
		return "", err
	}
	if writable {
		return "", fmt.Errorf("this service provider takes its NameID from %q, which a person can edit", attribute)
	}
	values, err := UserAttributes(ctx, tx, userID, orgID, root)
	if err != nil {
		return "", err
	}
	for _, v := range values {
		if v.Name == attribute && v.Value != "" {
			return v.Value, nil
		}
	}
	return "", fmt.Errorf("this service provider takes its NameID from %q and the account has no value for it", attribute)
}

// nameIDFromUsername is the one source that is not a declared attribute.
const nameIDFromUsername = "username"

// SetSAMLNameIDAttribute says where a provider's NameID comes from; empty is what its
// format alone decides. Refused for an attribute a person can edit, which would let
// them choose who they are at the provider, and for a transient format, which is a
// new identifier every session by definition.
func SetSAMLNameIDAttribute(ctx context.Context, q outpostDB, orgID, providerID, attribute string) error {
	var format string
	if err := q.QueryRow(ctx, `SELECT name_id_format FROM core.saml_providers
		WHERE id::text = $2 AND org_id = $1::uuid`, orgID, providerID).Scan(&format); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSAMLProviderUnknown
		}
		return err
	}
	if attribute != "" && attribute != nameIDFromUsername {
		var writable bool
		err := q.QueryRow(ctx, `SELECT user_writable FROM core.user_attribute_schema
			WHERE org_id = $1::uuid AND name = $2`, orgID, attribute).Scan(&writable)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return samlInvalid{fmt.Sprintf("the organisation declares no attribute %q", attribute)}
		case err != nil:
			return err
		case writable:
			return samlInvalid{fmt.Sprintf("people can edit %q, and a NameID from it would let them choose who "+
				"they are at this service provider", attribute)}
		}
	}
	if attribute != "" && format == "transient" {
		return samlInvalid{"a transient NameID is new every session, so it cannot come from an attribute"}
	}
	_, err := q.Exec(ctx, `UPDATE core.saml_providers SET name_id_attribute = NULLIF($3, ''), updated_at = now()
		WHERE id::text = $2 AND org_id = $1::uuid`, orgID, providerID, attribute)
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

// SAMLParticipant is one service provider's view of a session.
type SAMLParticipant struct {
	SID          string
	ProviderID   string
	EntityID     string
	SessionIndex string
	NameID       string
	// NameIDFormat is as the assertion carried it, empty on a row from before
	// this was kept.
	NameIDFormat string
	SLOURLs      []string
}

// FindSAMLSession resolves the session a LogoutRequest is about.
//
// Looked up by (provider, NameID), because those are the only handles the
// service provider has -- the NameID is pairwise, so it is meaningless at any
// other provider, which is exactly the property that makes this lookup safe.
// SessionIndex narrows further when supplied.
//
// Deliberately scoped to the requesting provider: without that, a provider
// could name a session it never participated in.
func FindSAMLSession(ctx context.Context, tx pgx.Tx, providerID, nameID, sessionIndex string) (sid, userID, orgID string, err error) {
	err = tx.QueryRow(ctx, `
		SELECT p.sid, s.user_id::text, p.org_id::text
		FROM core.saml_session_participants p
		JOIN core.sessions s ON s.sid = p.sid
		WHERE p.provider_id = $1::uuid
		  AND p.name_id = $2
		  AND ($3 = '' OR p.session_index = $3)
		  AND s.revoked_at IS NULL
		ORDER BY p.first_seen_at DESC
		LIMIT 1`, providerID, nameID, sessionIndex).Scan(&sid, &userID, &orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", pgx.ErrNoRows
		}
		return "", "", "", fmt.Errorf("finding the session for a logout request: %w", err)
	}
	return sid, userID, orgID, nil
}

// SAMLParticipantsForSession lists every provider this session reached, so
// logout can propagate.
//
// exclude is the provider that ASKED for the logout, which must not be sent a
// LogoutRequest of its own: it already knows, and telling it can bounce the
// exchange back and forth.
func SAMLParticipantsForSession(ctx context.Context, tx pgx.Tx, sid, exclude string) ([]SAMLParticipant, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.provider_id::text, sp.entity_id, p.session_index, p.name_id, COALESCE(p.name_id_format, ''),
		       COALESCE(array_agg(u.url) FILTER (WHERE u.url IS NOT NULL), '{}')
		FROM core.saml_session_participants p
		JOIN core.saml_providers sp ON sp.id = p.provider_id
		LEFT JOIN core.saml_slo_urls u ON u.provider_id = p.provider_id AND u.binding <> 'SOAP'
		WHERE p.sid = $1 AND ($2 = '' OR p.provider_id <> $2::uuid) AND sp.enabled
		GROUP BY p.provider_id, sp.entity_id, p.session_index, p.name_id, p.name_id_format`, sid, exclude)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SAMLParticipant
	for rows.Next() {
		var p SAMLParticipant
		if err := rows.Scan(&p.ProviderID, &p.EntityID, &p.SessionIndex, &p.NameID, &p.NameIDFormat, &p.SLOURLs); err != nil {
			return nil, err
		}
		p.SID = sid
		out = append(out, p)
	}
	return out, rows.Err()
}

// LogoutStep is one service provider still to be visited by a logout chain.
type LogoutStep struct {
	ProviderID   string `json:"provider_id"`
	EntityID     string `json:"entity_id"`
	SLOURL       string `json:"slo_url"`
	NameID       string `json:"name_id"`
	NameIDFormat string `json:"name_id_format,omitempty"`
	SessionIndex string `json:"session_index"`
}

// LogoutChain is the state of a front-channel logout in progress.
type LogoutChain struct {
	OrgID         string
	SID           string
	UserID        string
	Remaining     []LogoutStep
	Notified      []LogoutStep
	Failed        []LogoutStep
	FinalRedirect string
}

// BeginLogoutChain records the providers to visit and returns the token that
// identifies the chain.
//
// The token is returned in plaintext once and stored only as a hash -- the same
// rule this schema applies to every other value a client holds.
func BeginLogoutChain(ctx context.Context, tx pgx.Tx, c LogoutChain) (string, error) {
	token, err := newOpaqueID()
	if err != nil {
		return "", err
	}
	remaining, err := json.Marshal(c.Remaining)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.saml_logout_progress
			(token_hash, org_id, sid, user_id, remaining, final_redirect)
		VALUES ($1, $2::uuid, $3, NULLIF($4,'')::uuid, $5, NULLIF($6,''))`,
		sum[:], c.OrgID, c.SID, c.UserID, remaining, c.FinalRedirect); err != nil {
		return "", fmt.Errorf("recording the logout chain: %w", err)
	}
	return token, nil
}

// AdvanceLogoutChain marks the provider just visited and returns the next.
//
// One statement, so two browsers arriving at once cannot both be handed the same
// next step and send two LogoutRequests to the same provider. `ok` reports
// whether the chain exists and is unexpired; `next` is nil when it is finished.
func AdvanceLogoutChain(ctx context.Context, tx pgx.Tx, token string, previousFailed bool) (chain *LogoutChain, next *LogoutStep, ok bool, err error) {
	sum := sha256.Sum256([]byte(token))

	var remainingJSON, notifiedJSON, failedJSON []byte
	var c LogoutChain
	err = tx.QueryRow(ctx, `
		SELECT org_id::text, sid, COALESCE(user_id::text,''),
		       remaining, notified, failed, COALESCE(final_redirect,'')
		FROM core.saml_logout_progress
		WHERE token_hash = $1 AND expires_at > now()
		FOR UPDATE`, sum[:]).Scan(&c.OrgID, &c.SID, &c.UserID,
		&remainingJSON, &notifiedJSON, &failedJSON, &c.FinalRedirect)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	if err := json.Unmarshal(remainingJSON, &c.Remaining); err != nil {
		return nil, nil, false, err
	}
	_ = json.Unmarshal(notifiedJSON, &c.Notified)
	_ = json.Unmarshal(failedJSON, &c.Failed)

	// The head of `remaining` is the provider the browser has just come back
	// from -- it was moved there when we sent it, not when it answered.
	if len(c.Remaining) > 0 {
		done := c.Remaining[0]
		c.Remaining = c.Remaining[1:]
		if previousFailed {
			c.Failed = append(c.Failed, done)
		} else {
			c.Notified = append(c.Notified, done)
		}
	}

	remainingJSON, _ = json.Marshal(c.Remaining)
	notifiedJSON, _ = json.Marshal(c.Notified)
	failedJSON, _ = json.Marshal(c.Failed)
	if _, err := tx.Exec(ctx, `
		UPDATE core.saml_logout_progress
		SET remaining = $2, notified = $3, failed = $4
		WHERE token_hash = $1`, sum[:], remainingJSON, notifiedJSON, failedJSON); err != nil {
		return nil, nil, false, err
	}

	if len(c.Remaining) == 0 {
		// Finished. Deleted rather than left to expire: it is spent, and a spent
		// token that still resolves is a token somebody can replay.
		if _, err := tx.Exec(ctx,
			`DELETE FROM core.saml_logout_progress WHERE token_hash = $1`, sum[:]); err != nil {
			return nil, nil, false, err
		}
		return &c, nil, true, nil
	}
	return &c, &c.Remaining[0], true, nil
}

// SweepExpiredLogoutChains removes abandoned chains. Called by the janitor.
func SweepExpiredLogoutChains(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.saml_logout_progress WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.saml_logout_progress WHERE expires_at <= now()
		LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
