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

// LoadDuoIntegration reads and unseals an organisation's Duo configuration,
// through a pool or the sign-in walk's own transaction.
func LoadDuoIntegration(ctx context.Context, db rowQuerier, orgID string,
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
func DuoUsernameFor(ctx context.Context, db rowQuerier, userID string) (string, error) {
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

// SetDuoIntegration stores an organisation's Duo application, its secret
// already sealed, and turns it on. Behind `signari duo set` and the Admin API
// (6.07), each of which checks the keys against Duo first.
func SetDuoIntegration(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, clientID string, sealedSecret []byte, apiHost string, failOpen bool) error {
	_, err := q.Exec(ctx, `
		INSERT INTO core.duo_integrations (org_id, client_id, secret_enc, api_host, fail_open)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (org_id) DO UPDATE SET
			client_id = EXCLUDED.client_id, secret_enc = EXCLUDED.secret_enc,
			api_host = EXCLUDED.api_host, fail_open = EXCLUDED.fail_open,
			enabled = true, updated_at = now()`,
		orgID, clientID, sealedSecret, apiHost, failOpen)
	return err
}

// DuoSealedSecretOf is the Duo secret an organisation holds, still sealed,
// for a configuration file that changes the integration without naming the
// secret again: SetDuoIntegration writes it whole.
func DuoSealedSecretOf(ctx context.Context, db rowQuerier, orgID string) ([]byte, error) {
	var sealed []byte
	err := db.QueryRow(ctx, `SELECT secret_enc FROM core.duo_integrations WHERE org_id = $1::uuid`, orgID).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoDuoIntegration
	}
	return sealed, err
}

// DuoSecretOf opens it, so a plan can say whether the one a file names
// differs. Never shown.
func DuoSecretOf(ctx context.Context, db rowQuerier, root *keys.RootKey, orgID string) (string, error) {
	sealed, err := DuoSealedSecretOf(ctx, db, orgID)
	if err != nil {
		return "", err
	}
	if root == nil {
		return "", fmt.Errorf("the Duo secret is sealed and no root key is loaded")
	}
	plain, err := root.Open(sealed, "duo_secret")
	return string(plain), err
}

// RemoveDuoIntegration takes Duo away from an organisation, as a pruned
// configuration file asks (6.25). Its people's enrolments stay, for when it
// is set again.
func RemoveDuoIntegration(ctx context.Context, db interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID string) error {
	_, err := db.Exec(ctx, `DELETE FROM core.duo_integrations WHERE org_id = $1::uuid`, orgID)
	return err
}

// DuoIntegration is an organisation's Duo application as an operator sees it:
// never its secret.
type DuoIntegration struct {
	Configured, Enabled, FailOpen bool
	ClientID, APIHost             string
	Enrolled                      int
}

// DuoIntegrationOf reads it; Configured false when there is none.
func DuoIntegrationOf(ctx context.Context, db rowQuerier, orgID string) (DuoIntegration, error) {
	var d DuoIntegration
	err := db.QueryRow(ctx, `
		SELECT client_id, api_host, fail_open, enabled,
		       (SELECT count(*) FROM core.duo_enrollments e WHERE e.org_id = i.org_id)
		  FROM core.duo_integrations i WHERE org_id = $1::uuid`, orgID).
		Scan(&d.ClientID, &d.APIHost, &d.FailOpen, &d.Enabled, &d.Enrolled)
	if errors.Is(err, pgx.ErrNoRows) {
		return DuoIntegration{}, nil
	}
	d.Configured = err == nil
	return d, err
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
