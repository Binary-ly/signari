package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/passwords"
)

// Dynamic client registration storage, RFC 7591 / RFC 7592.

var (
	// ErrRegistrationClosed covers every reason a caller may not register: the
	// organisation has it turned off, the token is unknown, revoked, expired or
	// spent. One error, because distinguishing them lets a caller map where
	// registration is open.
	ErrRegistrationClosed = errors.New("registration is not available")
)

// RegistrationPolicy is what an organisation allows.
type RegistrationPolicy struct {
	Enabled           bool
	Open              bool
	MaxClients        int
	AllowedScopes     []string
	AllowConfidential bool
}

// LoadRegistrationPolicy returns the policy, or a closed one when there is none.
//
// Absent means closed, never open. A deployment that has never thought about
// dynamic registration must not have it switched on by a missing row.
func LoadRegistrationPolicy(ctx context.Context, db *pgxpool.Pool, orgID string) (*RegistrationPolicy, error) {
	p := &RegistrationPolicy{}
	err := db.QueryRow(ctx, `
		SELECT enabled, open, max_clients, allowed_scopes, allow_confidential
		FROM core.registration_policies WHERE org_id = $1::uuid`, orgID).
		Scan(&p.Enabled, &p.Open, &p.MaxClients, &p.AllowedScopes, &p.AllowConfidential)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &RegistrationPolicy{}, nil
		}
		return nil, err
	}
	return p, nil
}

// SingleOpenRegistrationOrg returns the one organisation with open registration.
//
// Exactly one, or nothing. With several, a request carrying no token names no
// organisation, and picking one would put a stranger's client in somebody's
// tenant on the strength of a guess.
func SingleOpenRegistrationOrg(ctx context.Context, db *pgxpool.Pool) (string, error) {
	rows, err := db.Query(ctx, `
		SELECT org_id::text FROM core.registration_policies
		WHERE enabled AND open LIMIT 2`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var found []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		found = append(found, id)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(found) != 1 {
		return "", ErrRegistrationClosed
	}
	return found[0], nil
}

// RedeemRegistrationToken checks an initial access token and spends one use.
func RedeemRegistrationToken(ctx context.Context, db *pgxpool.Pool, hash []byte) (orgID, tokenID string, err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var remaining *int
	err = tx.QueryRow(ctx, `
		SELECT t.id::text, t.org_id::text, t.remaining
		FROM core.registration_tokens t
		JOIN core.registration_policies p ON p.org_id = t.org_id
		WHERE t.token_hash = $1
		  AND t.revoked_at IS NULL
		  AND (t.expires_at IS NULL OR t.expires_at > now())
		  AND p.enabled
		FOR UPDATE OF t`, hash).Scan(&tokenID, &orgID, &remaining)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrRegistrationClosed
		}
		return "", "", err
	}
	if remaining != nil {
		if *remaining <= 0 {
			return "", "", ErrRegistrationClosed
		}
		if _, err := tx.Exec(ctx,
			`UPDATE core.registration_tokens SET remaining = remaining - 1 WHERE id = $1::uuid`,
			tokenID); err != nil {
			return "", "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return orgID, tokenID, nil
}

// CountDynamicClients is what the per-organisation ceiling is measured against.
func CountDynamicClients(ctx context.Context, db *pgxpool.Pool, orgID string) (int, error) {
	var n int
	err := db.QueryRow(ctx, `
		SELECT count(*) FROM core.clients
		WHERE org_id = $1::uuid AND dynamically_registered`, orgID).Scan(&n)
	return n, err
}

// NewClientRegistration is what the handler asks for.
type NewClientRegistration struct {
	OrgID        string
	DisplayName  string
	RedirectURIs []string
	Scopes       []string
	Confidential bool
	LogoutURI    string
	TokenID      string

	// DPoPBound is RFC 9449 §5.2's `dpop_bound_access_tokens`. A client may only
	// ever set this on itself, and setting it can only cause its own requests to
	// be refused, so it is safe to honour from open registration.
	DPoPBound bool
}

// RegisteredClient is what came back.
type RegisteredClient struct {
	ClientID          string
	DisplayName       string
	ClientSecret      string
	RegistrationToken string
	RedirectURIs      []string
	Scopes            []string
}

// RegisterClient creates a self-registered client.
func RegisterClient(ctx context.Context, db *pgxpool.Pool, in NewClientRegistration) (*RegisteredClient, error) {
	clientID, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	regToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	regHash := sha256.Sum256([]byte(regToken))

	out := &RegisteredClient{
		ClientID:          "dyn_" + clientID,
		DisplayName:       in.DisplayName,
		RegistrationToken: regToken,
		RedirectURIs:      in.RedirectURIs,
		Scopes:            in.Scopes,
	}

	kind := "public"
	var secretHash *string
	if in.Confidential {
		secret, serr := randomToken(32)
		if serr != nil {
			return nil, serr
		}
		// 32 bytes from the system random source -- 256 bits. Hashed by its
		// entropy rather than as though it were a password; see
		// internal/clients. Without this a dynamically registered client pays
		// 33 ms per token request while a CLI-created one pays under one,
		// which is an inconsistency nobody would predict from the outside.
		hashed, ok := clients.HashSecret(secret)
		if !ok {
			h := passwords.NewHasher(passwords.MemoryBudgetMiB)
			var herr error
			hashed, herr = h.Hash(ctx, secret)
			if herr != nil {
				return nil, herr
			}
		}
		kind = "confidential"
		secretHash = &hashed
		out.ClientSecret = secret
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO core.clients
			(client_id, org_id, display_name, client_type, client_secret_hash,
			 scopes, backchannel_logout_uri, dynamically_registered,
			 registration_token_hash, registered_at, dpop_bound_access_tokens)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, NULLIF($7,''), true, $8, now(), $9)`,
		out.ClientID, in.OrgID, in.DisplayName, kind, secretHash, in.Scopes,
		in.LogoutURI, regHash[:], in.DPoPBound); err != nil {
		return nil, fmt.Errorf("creating the client: %w", err)
	}

	for _, u := range in.RedirectURIs {
		// Dynamic registration is open to anybody who holds a registration
		// token, which makes it the LAST place to skip validation -- and it was
		// the only registration path with none at all.
		if err := clients.ValidateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("redirect_uri %q: %w", u, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)`, out.ClientID, u); err != nil {
			return nil, fmt.Errorf("registering redirect_uri %q: %w", u, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// LoadRegisteredClient finds a dynamically registered client by its management
// token.
//
// Both conditions matter: the token must match AND the client must be
// dynamically registered. Without the second, a leaked registration token could
// be pointed at an operator-created client id and read it back.
func LoadRegisteredClient(ctx context.Context, db *pgxpool.Pool, clientID string, tokenHash []byte) (*RegisteredClient, error) {
	c := &RegisteredClient{}
	err := db.QueryRow(ctx, `
		SELECT client_id, display_name, scopes
		FROM core.clients
		WHERE client_id = $1 AND dynamically_registered
		  AND registration_token_hash = $2`, clientID, tokenHash).
		Scan(&c.ClientID, &c.DisplayName, &c.Scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRegistrationClosed
		}
		return nil, err
	}
	if err := db.QueryRow(ctx, `
		SELECT array_agg(redirect_uri) FROM core.client_redirect_uris
		WHERE client_id = $1`, clientID).Scan(&c.RedirectURIs); err != nil {
		return nil, err
	}
	return c, nil
}

// DeleteRegisteredClient removes a self-registered client.
func DeleteRegisteredClient(ctx context.Context, db *pgxpool.Pool, clientID string) error {
	_, err := db.Exec(ctx,
		`DELETE FROM core.clients WHERE client_id = $1 AND dynamically_registered`, clientID)
	return err
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generating a token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AnyRegistrationEnabled reports whether dynamic registration is on anywhere.
//
// Discovery uses it to decide whether to advertise registration_endpoint. A
// document naming an endpoint that answers 401 to every possible caller is
// worse than one that omits it: the client tries, fails, and blames itself.
func AnyRegistrationEnabled(ctx context.Context, db *pgxpool.Pool) (bool, error) {
	var on bool
	err := db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM core.registration_policies WHERE enabled)`).Scan(&on)
	return on, err
}
