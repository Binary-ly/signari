package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/duo"
	"signari.dev/engine/internal/keys"
)

// Duo storage.
//
// Three things, and the second is the one that makes the integration safe:
//
//	duo_integrations   the organisation's keys and its fail-open decision
//	duo_enrollments    which local user is which Duo username
//	duo_challenges     an in-flight prompt, single-use
//
// Without the enrollment mapping there is nothing to compare Duo's answer
// against, and "Duo said somebody authenticated" is not a statement about the
// account being signed into.

var (
	ErrNoDuoIntegration = errors.New("no Duo integration is configured")
	ErrNoDuoEnrollment  = errors.New("this user is not enrolled in Duo")
)

// DuoChallenge is an in-flight prompt.
type DuoChallenge struct {
	State       string
	UserID      string
	OrgID       string
	DuoUsername string
	Authz       string
	AMRSoFar    []string
}

// LoadDuoIntegration reads and unseals an organisation's Duo configuration.
func LoadDuoIntegration(ctx context.Context, db *pgxpool.Pool, orgID string,
	root *keys.RootKey, redirectURI string, allowInsecure bool) (*duo.Config, error) {

	var clientID, apiHost string
	var sealed []byte
	var failOpen bool
	err := db.QueryRow(ctx, `
		SELECT client_id, secret_enc, api_host, fail_open
		FROM core.duo_integrations WHERE org_id = $1::uuid AND enabled`, orgID).
		Scan(&clientID, &sealed, &apiHost, &failOpen)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoDuoIntegration
		}
		return nil, err
	}

	secret, err := root.Open(sealed, "duo_secret")
	if err != nil {
		return nil, fmt.Errorf("unsealing the Duo secret: %w", err)
	}
	cfg := &duo.Config{
		ClientID: clientID, ClientSecret: string(secret), APIHost: apiHost,
		RedirectURI: redirectURI, FailOpen: failOpen,
	}
	// A local stand-in, for development only. The override refuses unless the
	// deployment has already declared itself insecure, so this cannot take
	// effect anywhere real.
	if base := os.Getenv("SIGNARI_DUO_BASE_URL"); base != "" {
		if err := cfg.SetInsecureBaseURL(base, allowInsecure); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// DuoUsernameFor returns the Duo username for a local user.
func DuoUsernameFor(ctx context.Context, db *pgxpool.Pool, userID string) (string, error) {
	var name string
	err := db.QueryRow(ctx,
		`SELECT duo_username FROM core.duo_enrollments WHERE user_id = $1::uuid`,
		userID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoDuoEnrollment
	}
	return name, err
}

// EnrollDuo maps a local user to a Duo username.
//
// Takes the narrow exec interface rather than pgx.Tx so the CLI can call it
// too. The first version could not, so the CLI wrote its own INSERT -- two
// statements to keep in step, and the second one is where the ON CONFLICT
// clause goes missing.
func EnrollDuo(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, userID, orgID, duoUsername string) error {
	_, err := q.Exec(ctx, `
		INSERT INTO core.duo_enrollments (user_id, org_id, duo_username)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (user_id) DO UPDATE SET duo_username = EXCLUDED.duo_username`,
		userID, orgID, duoUsername)
	return err
}

// BeginDuoChallenge records an in-flight prompt.
func BeginDuoChallenge(ctx context.Context, db *pgxpool.Pool, c DuoChallenge,
	ttl time.Duration) error {

	_, err := db.Exec(ctx, `
		INSERT INTO core.duo_challenges
			(state, user_id, org_id, duo_username, authz, amr_so_far, expires_at)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, now() + $7::interval)`,
		c.State, c.UserID, c.OrgID, c.DuoUsername, c.Authz, c.AMRSoFar,
		fmt.Sprintf("%d seconds", int(ttl.Seconds())))
	return err
}

// ConsumeDuoChallenge claims a challenge, exactly once.
//
// The UPDATE is the claim. Reading and then marking used leaves a window in
// which the same Duo response can be presented twice -- which a browser
// double-submitting produces by accident and an attacker produces on purpose.
func ConsumeDuoChallenge(ctx context.Context, db *pgxpool.Pool, state string) (
	*DuoChallenge, error) {

	c := &DuoChallenge{}
	err := db.QueryRow(ctx, `
		UPDATE core.duo_challenges SET consumed_at = now()
		WHERE state = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING state, user_id::text, org_id::text, duo_username, authz, amr_so_far`,
		state).Scan(&c.State, &c.UserID, &c.OrgID, &c.DuoUsername, &c.Authz, &c.AMRSoFar)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no Duo challenge is in progress for this browser: it " +
			"may have expired, already been completed, or been started elsewhere")
	}
	return c, err
}

// PurgeExpiredDuoChallenges drops challenges nobody finished.
func PurgeExpiredDuoChallenges(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.duo_challenges WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
