package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/extfactor"
	"signari.dev/engine/internal/flow"
)

// The services an external_factor stage sends somebody to (10.03), behind
// `signari external-factor`, the Admin API and `external_factors:` in a
// configuration file. internal/extfactor says what is believed and why.

var (
	// ErrInvalidExternalFactor is a registration that could never be answered,
	// or that would let a service claim more than a factor may.
	ErrInvalidExternalFactor = errors.New("invalid external factor")
	// ErrNoExternalFactor is a name this organisation has not registered.
	ErrNoExternalFactor = errors.New("no such external factor")
	// ErrExternalFactorInUse is a factor the organisation's flow still names.
	ErrExternalFactorInUse = errors.New("the sign-in flow names this external factor")
)

// ExternalFactor is one registered service.
type ExternalFactor struct {
	Name string
	// URL is where the browser is sent, with `challenge` added.
	URL string
	// Issuer is the iss an answer must carry, and the challenge's aud.
	Issuer string
	// JWKS is the service's public key set.
	JWKS []byte
	// AMR is the most it may claim to have proved.
	AMR       []string
	CreatedAt time.Time
}

// CheckExternalFactor is what registering one refuses. It answers how many keys
// the set holds.
func CheckExternalFactor(f ExternalFactor) (int, error) {
	if f.Name == "" || strings.TrimSpace(f.Name) != f.Name || strings.ContainsAny(f.Name, " /:") {
		return 0, fmt.Errorf("%w: it needs a name, with no spaces, slashes or colons", ErrInvalidExternalFactor)
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return 0, fmt.Errorf("%w: its url must be https, with no user information or fragment", ErrInvalidExternalFactor)
	}
	if f.Issuer == "" {
		return 0, fmt.Errorf("%w: it needs the issuer its answers are signed as", ErrInvalidExternalFactor)
	}
	if err := extfactor.CheckDeclared(f.AMR); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidExternalFactor, err)
	}
	keys, err := extfactor.CheckKeys(f.JWKS)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidExternalFactor, err)
	}
	return keys, nil
}

// SetExternalFactor registers a service, or replaces what is registered under
// its name. It answers how many keys the set holds.
func SetExternalFactor(ctx context.Context, tx Execer, orgID string, f ExternalFactor) (int, error) {
	keys, err := CheckExternalFactor(f)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO core.external_factors (org_id, name, url, issuer, jwks, amr)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, name) DO UPDATE SET url = EXCLUDED.url, issuer = EXCLUDED.issuer,
			jwks = EXCLUDED.jwks, amr = EXCLUDED.amr`,
		orgID, f.Name, f.URL, f.Issuer, f.JWKS, f.AMR)
	return keys, err
}

// ExternalFactors reads an organisation's services, by name.
func ExternalFactors(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, orgID string) ([]ExternalFactor, error) {
	rows, err := q.Query(ctx, `SELECT name, url, issuer, jwks, amr, created_at FROM core.external_factors
		WHERE org_id = $1::uuid ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExternalFactor{}
	for rows.Next() {
		var f ExternalFactor
		if err := rows.Scan(&f.Name, &f.URL, &f.Issuer, &f.JWKS, &f.AMR, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LoadExternalFactor reads one service.
func LoadExternalFactor(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID, name string) (*ExternalFactor, error) {
	f := &ExternalFactor{Name: name}
	err := q.QueryRow(ctx, `SELECT url, issuer, jwks, amr, created_at FROM core.external_factors
		WHERE org_id = $1::uuid AND name = $2`, orgID, name).
		Scan(&f.URL, &f.Issuer, &f.JWKS, &f.AMR, &f.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoExternalFactor
	}
	return f, err
}

// RemoveExternalFactor forgets a service, reporting whether it was registered.
// While the organisation's flow names it the answer is ErrExternalFactorInUse:
// removing it then would refuse everybody who reached that stage.
func RemoveExternalFactor(ctx context.Context, q outpostDB, orgID, name string) (bool, error) {
	f, err := SignInFlowOf(ctx, q, orgID)
	if err != nil {
		return false, err
	}
	if f.Document != "" {
		if file, perr := flow.Parse([]byte(f.Document)); perr == nil {
			if fl, ok := file.For(flow.Authentication); ok && slices.Contains(fl.Factors(), name) {
				return false, fmt.Errorf("%w: apply a flow without it first", ErrExternalFactorInUse)
			}
		}
	}
	tag, err := q.Exec(ctx, `DELETE FROM core.external_factors WHERE org_id = $1::uuid AND name = $2`, orgID, name)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func factorNonceHash(nonce string) []byte {
	return HashToken("external_factor:" + nonce)
}

// FactorLoginHint is how a person signs in, for a challenge to say: their
// username, or else their address, or nothing when they have neither.
func FactorLoginHint(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (string, error) {
	var hint string
	err := q.QueryRow(ctx, `SELECT COALESCE(username, email, '') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&hint)
	return hint, err
}

// BeginFactorChallenge records a nonce waiting to come back.
func BeginFactorChallenge(ctx context.Context, q Execer, orgID, factor, userID, nonce string, ttl time.Duration) error {
	_, err := q.Exec(ctx, `
		INSERT INTO core.external_factor_challenges (nonce_hash, org_id, factor, user_id, expires_at)
		VALUES ($1, $2::uuid, $3, $4::uuid, now() + make_interval(secs => $5))`,
		factorNonceHash(nonce), orgID, factor, userID, ttl.Seconds())
	return err
}

// SpendFactorChallenge claims a nonce, exactly once, for the person and service
// it was issued for. False is an answer replayed, expired or addressed to
// another sign-in.
//
// Committed on its own and never in the sign-in's transaction, which a later
// stage abandons: the nonce would come back to life with it.
func SpendFactorChallenge(ctx context.Context, q Execer, orgID, factor, userID, nonce string) (bool, error) {
	tag, err := q.Exec(ctx, `
		DELETE FROM core.external_factor_challenges
		 WHERE nonce_hash = $1 AND org_id = $2::uuid AND factor = $3 AND user_id = $4::uuid
		   AND expires_at > now()`,
		factorNonceHash(nonce), orgID, factor, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// SweepExpiredFactorChallenges deletes nonces nobody came back with.
func SweepExpiredFactorChallenges(ctx context.Context, tx pgx.Tx, limit int) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM core.external_factor_challenges WHERE ctid = ANY(ARRAY(
		SELECT ctid FROM core.external_factor_challenges WHERE expires_at < now() LIMIT $1 FOR UPDATE SKIP LOCKED))`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
