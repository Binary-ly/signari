// Package importer reads a realm export from another identity provider and
// creates the equivalent users and clients here.
//
// The point is that an import is boring. Everything it produces goes through the
// same code paths as anything else: users get a password hash the normal
// verifier understands, clients get their existing id and secret so downstream
// applications keep working, and the first successful sign-in upgrades the hash
// to Argon2id like any other foreign format.
//
// Two rules, both learned from how imports actually go wrong:
//
//  1. IDEMPOTENT. Re-running must not duplicate anyone. Imports are re-run --
//     after a partial failure, after a dry run, after someone finds one more
//     realm -- and an importer that duplicates users on the second pass is one
//     nobody dares use twice.
//  2. REPORT, DO NOT GUESS. A user with an unsupported credential type is
//     skipped and named, not imported without a password. Silently creating an
//     account nobody can sign in to is worse than refusing it.
package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"signari.dev/engine/internal/clients"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/passwords"
)

// KeycloakRealm is the subset of a realm export this reads. Deliberately
// partial: a realm export has hundreds of fields, and parsing ones we cannot act
// on would only invite the impression that we honoured them.
type KeycloakRealm struct {
	Realm   string           `json:"realm"`
	Users   []keycloakUser   `json:"users"`
	Clients []keycloakClient `json:"clients"`
}

type keycloakUser struct {
	Username      string               `json:"username"`
	Email         string               `json:"email"`
	FirstName     string               `json:"firstName"`
	LastName      string               `json:"lastName"`
	Enabled       bool                 `json:"enabled"`
	EmailVerified bool                 `json:"emailVerified"`
	Credentials   []keycloakCredential `json:"credentials"`
}

type keycloakCredential struct {
	Type           string `json:"type"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

type keycloakClient struct {
	ClientID              string   `json:"clientId"`
	Secret                string   `json:"secret"`
	Enabled               bool     `json:"enabled"`
	PublicClient          bool     `json:"publicClient"`
	RedirectURIs          []string `json:"redirectUris"`
	StandardFlowEnabled   bool     `json:"standardFlowEnabled"`
	ServiceAccountEnabled bool     `json:"serviceAccountsEnabled"`
}

// Result is what happened, in enough detail to act on.
type Result struct {
	UsersCreated   int
	UsersUpdated   int
	UsersSkipped   []string
	ClientsCreated int
	ClientsSkipped []string
}

// Parse reads a realm export.
func Parse(r io.Reader) (*KeycloakRealm, error) {
	var realm KeycloakRealm
	// Unknown fields are ignored rather than rejected: a realm export from a
	// different Keycloak version has fields we have never heard of, and refusing
	// the whole file over one of them would make this useless in practice.
	if err := json.NewDecoder(r).Decode(&realm); err != nil {
		return nil, fmt.Errorf("importer: reading realm export: %w", err)
	}
	if realm.Realm == "" && len(realm.Users) == 0 && len(realm.Clients) == 0 {
		return nil, fmt.Errorf("importer: this does not look like a Keycloak realm export")
	}
	return &realm, nil
}

// Import creates users and clients from a parsed realm.
//
// Runs in ONE transaction: a half-imported realm is the worst outcome, because
// nobody can tell which half, and the natural response -- run it again -- is
// exactly what an idempotent importer is for but a partial one punishes.
func Import(ctx context.Context, tx pgx.Tx, orgID string, realm *KeycloakRealm,
	hasher *passwords.Hasher, dryRun bool) (*Result, error) {
	res := &Result{}

	for _, u := range realm.Users {
		identifier := u.Email
		if identifier == "" {
			identifier = u.Username
		}
		if identifier == "" {
			res.UsersSkipped = append(res.UsersSkipped, "(a user with no username or email)")
			continue
		}
		if !u.Enabled {
			// Disabled in Keycloak means disabled here. Importing them as active
			// would silently re-enable accounts somebody deliberately turned off.
			res.UsersSkipped = append(res.UsersSkipped, identifier+" (disabled in the realm)")
			continue
		}

		hash, ok := keycloakPasswordHash(u)
		if !ok {
			// Named, not silently imported without a credential: an account
			// nobody can sign in to is worse than one that was refused.
			res.UsersSkipped = append(res.UsersSkipped,
				identifier+" (no importable password; they must use recovery or delegated sign-in)")
			continue
		}
		if dryRun {
			res.UsersCreated++
			continue
		}

		var userID string
		var inserted bool
		err := tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, email, username, user_handle, email_verified_at, migration_state)
			VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''),
			        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
			        CASE WHEN $4 THEN now() ELSE NULL END, 'pending')
			-- Matches users_org_email_key exactly: a PARTIAL unique index on
			-- (org_id, lower(email)). The conflict target must mirror the index
			-- expression and its WHERE clause, or PostgreSQL cannot use it and the
			-- import fails on the first existing user -- which is precisely the
			-- re-run an idempotent importer exists to make safe.
			ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
			DO UPDATE SET username = COALESCE(core.users.username, EXCLUDED.username)
			RETURNING id::text, (xmax = 0)`,
			orgID, strings.ToLower(u.Email), u.Username, u.EmailVerified).Scan(&userID, &inserted)
		if err != nil {
			return nil, fmt.Errorf("importer: creating user %s: %w", identifier, err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, source_system, is_current)
			VALUES ($1::uuid, $2::uuid, $3, 'keycloak', 'keycloak', false)
			ON CONFLICT (user_id) DO UPDATE SET
				hash = EXCLUDED.hash, algorithm = 'keycloak',
				source_system = 'keycloak', is_current = false, updated_at = now()`,
			userID, orgID, hash); err != nil {
			return nil, fmt.Errorf("importer: storing credential for %s: %w", identifier, err)
		}

		if inserted {
			res.UsersCreated++
		} else {
			res.UsersUpdated++
		}
	}

	for _, c := range realm.Clients {
		if c.ClientID == "" || !c.StandardFlowEnabled {
			// Only the authorization code flow is imported. A client configured
			// for a flow we do not implement would be created here in a shape
			// that cannot work, which is worse than leaving it out and saying so.
			res.ClientsSkipped = append(res.ClientsSkipped,
				c.ClientID+" (not using the authorization code flow)")
			continue
		}
		if dryRun {
			res.ClientsCreated++
			continue
		}

		kind := "confidential"
		if c.PublicClient {
			kind = "public"
		}
		// The application keeps the secret it already has -- that is the point of
		// the whole feature -- but it is HASHED before storage, exactly like one
		// we generated.
		//
		// The first version of this wrote the plaintext into client_secret_hash.
		// Two things were wrong with that and only one of them is obvious: a
		// plaintext secret sat in a column named `_hash`, AND the Argon2 verifier
		// correctly refused it, so every imported client silently could not
		// authenticate. "Verbatim import" meant "verbatim and unusable".
		secretHash := ""
		if c.Secret != "" {
			h, herr := hasher.Hash(ctx, c.Secret)
			if herr != nil {
				return nil, fmt.Errorf("importer: hashing the secret for %s: %w", c.ClientID, herr)
			}
			secretHash = h
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.clients (client_id, org_id, display_name, client_type,
			                          client_secret_hash, enabled, grant_types, scopes, require_pkce)
			VALUES ($1, $2::uuid, $1, $3, $4, $5,
			        ARRAY['authorization_code','refresh_token'],
			        ARRAY['openid','profile','email'], $6)
			ON CONFLICT (client_id) DO NOTHING`,
			c.ClientID, orgID, kind, secretHash, c.Enabled, c.PublicClient); err != nil {
			return nil, fmt.Errorf("importer: creating client %s: %w", c.ClientID, err)
		}
		for _, u := range c.RedirectURIs {
			// An import brings somebody else's registrations, and Keycloak
			// permits shapes we do not: wildcards, and redirect URIs carrying
			// response parameters.
			//
			// SKIPPED AND REPORTED rather than fatal. A migration that dies on
			// one bad URI out of four hundred is a migration nobody finishes,
			// and the operator needs the list of what did not come across --
			// which is exactly what ClientsSkipped is.
			if verr := clients.ValidateRedirectURI(u); verr != nil {
				res.ClientsSkipped = append(res.ClientsSkipped,
					c.ClientID+" redirect "+u+" ("+verr.Error()+")")
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
				VALUES ($1, $2) ON CONFLICT DO NOTHING`, c.ClientID, u); err != nil {
				return nil, fmt.Errorf("importer: redirect for %s: %w", c.ClientID, err)
			}
		}
		res.ClientsCreated++
	}

	return res, nil
}

// keycloakPasswordHash extracts a usable password credential.
func keycloakPasswordHash(u keycloakUser) (string, bool) {
	for _, c := range u.Credentials {
		if c.Type != "password" || c.SecretData == "" || c.CredentialData == "" {
			continue
		}
		return passwords.EncodeKeycloak(c.CredentialData, c.SecretData), true
	}
	return "", false
}
