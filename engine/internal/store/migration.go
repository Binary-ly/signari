package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/delegated"
	"signari.dev/engine/internal/keys"
)

// migrationSecretContext binds an encrypted client secret to its purpose, so a
// blob moved between columns fails to decrypt rather than silently becoming a
// different secret.
const migrationSecretContext = "migration_source_secret"

// PendingMigration is a user who exists here but whose password still lives at
// the old provider.
type PendingMigration struct {
	UserID string
	OrgID  string
	Source delegated.Source
}

// LookupMigrationCandidate finds a user with no usable local credential whose
// organisation has delegated authentication configured.
//
// The distinction from lookupCredential is the whole point: "no such user" and
// "a user we imported but have no password for" look identical at the login
// form and must be handled completely differently.
//
// Returns ok=false for everything else -- an unknown identifier, a user with a
// local hash, a disabled source. No fallback, no guessing: delegation is
// attempted only where it was explicitly configured.
//
// Scoped to orgID, the sign-in page's organisation, as the local credential
// lookup is (1.13b). Empty means the page belongs to no organisation in
// particular, and then the identifier must name exactly one candidate: two
// would mean sending this password to whichever tenant's old provider the
// database returned first.
func LookupMigrationCandidate(ctx context.Context, db *pgxpool.Pool, orgID, identifier string,
	root *keys.RootKey) (*PendingMigration, bool, error) {

	var p PendingMigration
	var secretEnc []byte

	rows, err := db.Query(ctx, `
		SELECT u.id::text, u.org_id::text,
		       ms.id::text, ms.kind, ms.display_name, ms.token_endpoint,
		       COALESCE(ms.client_id, ''), ms.client_secret_enc, ms.scope,
		       COALESCE(ms.bind_dn_template, ''), ms.start_tls, COALESCE(ms.ca_pem, '')
		FROM core.users u
		JOIN core.migration_sources ms ON ms.org_id = u.org_id
		LEFT JOIN core.password_credentials pc ON pc.user_id = u.id
		WHERE u.status = 'active'
		  AND u.migration_state = 'pending'
		  AND ms.enabled
		  -- No local credential to check. A user who HAS one is authenticated
		  -- locally; delegating for them would send their password to a third
		  -- party we no longer need to ask.
		  AND pc.user_id IS NULL
		  AND (lower(u.email) = lower($1) OR lower(u.username) = lower($1))
		  AND ($2 = '' OR u.org_id = $2::uuid)
		LIMIT 2`, identifier, orgID)
	if err != nil {
		return nil, false, fmt.Errorf("looking up migration candidate: %w", err)
	}
	found := 0
	for rows.Next() {
		found++
		if err := rows.Scan(&p.UserID, &p.OrgID, &p.Source.ID, &p.Source.Kind,
			&p.Source.DisplayName, &p.Source.TokenEndpoint, &p.Source.ClientID,
			&secretEnc, &p.Source.Scope, &p.Source.BindDNTemplate, &p.Source.StartTLS,
			&p.Source.CAPEM); err != nil {
			rows.Close()
			return nil, false, fmt.Errorf("looking up migration candidate: %w", err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("looking up migration candidate: %w", err)
	}
	if found != 1 {
		return nil, false, nil
	}

	if len(secretEnc) > 0 {
		// Unwrapped with the ROOT key, not a subject key: this secret belongs to
		// the organisation's migration configuration, not to any person, and it
		// must survive a user being crypto-shredded.
		secret, err := root.Open(secretEnc, migrationSecretContext)
		if err != nil {
			return nil, false, fmt.Errorf("unwrapping the migration source secret "+
				"(is the root key correct?): %w", err)
		}
		p.Source.ClientSecret = string(secret)
	}
	return &p, true, nil
}

// MigrationSourceConfig is an organisation's old provider as an operator sets
// it (2.01): `signari migration-source add` and the Admin API's PUT both write
// through SetMigrationSource. Nothing could create one before, so delegated
// verification, built and tested, could not be switched on.
type MigrationSourceConfig struct {
	// Kind is "oidc_password" or "ldap".
	Kind        string
	DisplayName string
	// URL is the token endpoint (https) or the directory (ldaps://, or
	// ldap:// with StartTLS).
	URL string
	// oidc_password only. An empty ClientSecret keeps the one stored.
	ClientID, ClientSecret, Scope string
	// ldap only.
	BindDNTemplate string
	StartTLS       bool
	CAPEM          string
}

// ErrInvalidMigrationSource is a source the verifier would refuse to use.
var ErrInvalidMigrationSource = errors.New("invalid migration source")

// ErrMigrationSourceUnknown is a change to a source an organisation lacks.
var ErrMigrationSourceUnknown = errors.New("this organisation has no migration source")

func invalidSource(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidMigrationSource, fmt.Sprintf(format, args...))
}

// validate holds a configuration to what delegated.Verify will use, so the
// mistake is reported to the person configuring it rather than to every user
// at their first sign-in. The schema's shape CHECK says the same, for a row
// written by hand.
func (c *MigrationSourceConfig) validate() error {
	if strings.TrimSpace(c.DisplayName) == "" {
		return invalidSource("give it a name, which the cutover figures are reported under")
	}
	lower := strings.ToLower(c.URL)
	switch c.Kind {
	case "oidc_password":
		if !strings.HasPrefix(lower, "https://") {
			return invalidSource("the token endpoint must be https: the request carries the user's password")
		}
		if c.ClientID == "" {
			return invalidSource("give the client id the old provider issued")
		}
		if c.BindDNTemplate != "" || c.CAPEM != "" || c.StartTLS {
			return invalidSource("a bind DN template, StartTLS and a CA are for an ldap source")
		}
		if c.Scope == "" {
			c.Scope = "openid"
		}
	case "ldap":
		if !strings.HasPrefix(lower, "ldaps://") && !(strings.HasPrefix(lower, "ldap://") && c.StartTLS) {
			return invalidSource("the directory must be ldaps://, or ldap:// with StartTLS: a plaintext " +
				"simple bind puts the user's password on the wire in the clear")
		}
		if strings.Count(c.BindDNTemplate, "{username}") != 1 || !strings.Contains(c.BindDNTemplate, "=") {
			return invalidSource("the bind DN template is a DN with {username} once, such as " +
				"uid={username},ou=people,dc=example,dc=com")
		}
		if c.ClientID != "" || c.ClientSecret != "" {
			return invalidSource("a client id and secret are for an oidc_password source")
		}
		if strings.HasPrefix(lower, "ldaps://") {
			// Already TLS from the first byte; recording StartTLS as well
			// would describe an upgrade that never happens.
			c.StartTLS = false
		}
		if c.CAPEM != "" {
			if block, _ := pem.Decode([]byte(c.CAPEM)); block == nil || block.Type != "CERTIFICATE" {
				return invalidSource("the CA is not a PEM certificate")
			} else if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return invalidSource("the CA does not parse: %v", err)
			}
		}
		c.Scope = "openid"
	default:
		return invalidSource("the kind is oidc_password or ldap, not %q", c.Kind)
	}
	return nil
}

// SetMigrationSource creates or replaces an organisation's one source. A new
// source is disabled, because a live one forwards every unmigrated user's
// password to a third party (0014); a replaced one keeps its state.
func SetMigrationSource(ctx context.Context, tx pgx.Tx, root *keys.RootKey, orgID string,
	c MigrationSourceConfig) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	var sealed []byte
	if c.ClientSecret != "" {
		if root == nil {
			return "", fmt.Errorf("a client secret is sealed under the root key, and none is loaded")
		}
		var err error
		if sealed, err = root.Seal([]byte(c.ClientSecret), migrationSecretContext); err != nil {
			return "", err
		}
	}
	// A stored secret was issued by the provider it was configured for. A
	// change of endpoint, client id or kind that brings no secret of its own
	// would send it to whoever the new endpoint is, so it is refused: neither
	// carried over nor dropped, which would fail every migrating sign-in with
	// no word of why.
	if c.ClientSecret == "" && c.Kind == "oidc_password" {
		var kind, endpoint string
		var oldClientID *string
		var hasSecret bool
		err := tx.QueryRow(ctx, `
			SELECT kind, token_endpoint, client_id, client_secret_enc IS NOT NULL
			FROM core.migration_sources WHERE org_id = $1::uuid FOR UPDATE`, orgID).
			Scan(&kind, &endpoint, &oldClientID, &hasSecret)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
		if err == nil && hasSecret &&
			(kind != c.Kind || endpoint != c.URL || oldClientID == nil || *oldClientID != c.ClientID) {
			return "", invalidSource("the token endpoint or client id changed, so give the client " +
				"secret again: the stored one was issued for the old provider and is sent nowhere else")
		}
	}
	var clientID, template, ca *string
	if c.ClientID != "" {
		clientID = &c.ClientID
	}
	if c.BindDNTemplate != "" {
		template = &c.BindDNTemplate
	}
	if c.CAPEM != "" {
		ca = &c.CAPEM
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO core.migration_sources (org_id, kind, display_name, token_endpoint, client_id,
		        client_secret_enc, scope, bind_dn_template, start_tls, ca_pem)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id) DO UPDATE SET
			kind = EXCLUDED.kind, display_name = EXCLUDED.display_name,
			token_endpoint = EXCLUDED.token_endpoint, client_id = EXCLUDED.client_id,
			client_secret_enc = CASE WHEN EXCLUDED.kind = 'ldap' THEN NULL
			                         ELSE COALESCE(EXCLUDED.client_secret_enc, migration_sources.client_secret_enc) END,
			scope = EXCLUDED.scope, bind_dn_template = EXCLUDED.bind_dn_template,
			start_tls = EXCLUDED.start_tls, ca_pem = EXCLUDED.ca_pem, updated_at = now()
		RETURNING id::text`,
		orgID, c.Kind, c.DisplayName, c.URL, clientID, sealed, c.Scope, template, c.StartTLS && c.Kind == "ldap", ca).
		Scan(&id)
	return id, err
}

// SetMigrationSourceEnabled switches delegation on or off.
func SetMigrationSourceEnabled(ctx context.Context, tx pgx.Tx, orgID string, enabled bool) error {
	tag, err := tx.Exec(ctx, `UPDATE core.migration_sources SET enabled = $2, updated_at = now()
		WHERE org_id = $1::uuid`, orgID, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMigrationSourceUnknown
	}
	return nil
}

// RemoveMigrationSource deletes the source. Users still pending stay pending,
// and are refused a password sign-in until they reset or a source returns.
func RemoveMigrationSource(ctx context.Context, tx pgx.Tx, orgID string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM core.migration_sources WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMigrationSourceUnknown
	}
	return nil
}

// MigrationSourceStatus is a source as it is reported: its settings without
// the secret, and how the cutover is going.
type MigrationSourceStatus struct {
	Kind           string `json:"kind"`
	DisplayName    string `json:"display_name"`
	URL            string `json:"url"`
	ClientID       string `json:"client_id,omitempty"`
	HasSecret      bool   `json:"has_client_secret"`
	Scope          string `json:"scope,omitempty"`
	BindDNTemplate string `json:"bind_dn_template,omitempty"`
	StartTLS       bool   `json:"start_tls"`
	HasCA          bool   `json:"has_ca"`
	Enabled        bool   `json:"enabled"`
	Successes      int64  `json:"delegated_successes"`
	Failures       int64  `json:"delegated_failures"`
	LastError      string `json:"last_error,omitempty"`
	Pending        int64  `json:"users_pending"`
	Migrated       int64  `json:"users_migrated"`
}

// MigrationSourceOf reports an organisation's source.
func MigrationSourceOf(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (*MigrationSourceStatus, error) {
	var s MigrationSourceStatus
	var clientID, scope, template *string
	err := q.QueryRow(ctx, `
		SELECT ms.kind, ms.display_name, ms.token_endpoint, ms.client_id, ms.client_secret_enc IS NOT NULL,
		       ms.scope, ms.bind_dn_template, ms.start_tls, ms.ca_pem IS NOT NULL, ms.enabled,
		       ms.delegated_successes, ms.delegated_failures, COALESCE(ms.last_error, ''),
		       (SELECT count(*) FROM core.users u WHERE u.org_id = ms.org_id AND u.migration_state = 'pending'),
		       (SELECT count(*) FROM core.users u WHERE u.org_id = ms.org_id AND u.migration_source_id = ms.id
		                                        AND u.migration_state = 'complete')
		FROM core.migration_sources ms WHERE ms.org_id = $1::uuid`, orgID).
		Scan(&s.Kind, &s.DisplayName, &s.URL, &clientID, &s.HasSecret, &scope, &template, &s.StartTLS,
			&s.HasCA, &s.Enabled, &s.Successes, &s.Failures, &s.LastError, &s.Pending, &s.Migrated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMigrationSourceUnknown
	}
	if err != nil {
		return nil, err
	}
	if clientID != nil {
		s.ClientID = *clientID
	}
	if template != nil {
		s.BindDNTemplate = *template
	}
	if scope != nil && s.Kind == "oidc_password" {
		s.Scope = *scope
	}
	return &s, nil
}

// CompleteMigration records a successful delegated sign-in.
//
// Writes the local hash, flips the user to 'complete', and stamps migrated_at --
// all in the caller's transaction, alongside the session being created. If any
// of it rolled back while the session committed, the user would be signed in and
// still have no local credential, and would be delegated again next time. The
// old provider would then have to stay alive forever, which is the one thing
// this feature exists to avoid.
func CompleteMigration(ctx context.Context, tx pgx.Tx, userID, orgID, sourceID, hash string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, source_system, is_current)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id', 'migrated', true)
		ON CONFLICT (user_id) DO UPDATE SET
			hash = EXCLUDED.hash, algorithm = 'argon2id', is_current = true, updated_at = now()`,
		userID, orgID, hash); err != nil {
		return fmt.Errorf("storing the migrated credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.users
		SET migration_state = 'complete', migrated_at = now(), migration_source_id = $2::uuid
		WHERE id = $1::uuid`, userID, sourceID); err != nil {
		return fmt.Errorf("marking the user migrated: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core.migration_sources
		SET delegated_successes = delegated_successes + 1, last_used_at = now(), last_error = NULL
		WHERE id = $1::uuid`, sourceID); err != nil {
		return fmt.Errorf("counting the delegated success: %w", err)
	}
	return nil
}

// RecordDelegationFailure counts a failure against the SOURCE, not the user.
//
// Separate from the per-account login throttle on purpose: a source that is
// down, misconfigured or rate-limiting us produces failures that say nothing
// about any user, and charging them to the user would lock out an entire
// organisation during someone else's outage.
func RecordDelegationFailure(ctx context.Context, db *pgxpool.Pool, sourceID, reason string) {
	_, _ = db.Exec(ctx, `
		UPDATE core.migration_sources
		SET delegated_failures = delegated_failures + 1, last_used_at = now(), last_error = $2
		WHERE id = $1::uuid`, sourceID, reason)
}
