package importer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// What every importer writes, one way (6.20): a person found or made, a
// group, a membership, an OTP seed, a passkey, a link to an upstream
// provider. Each answers why when it cannot, for the report.

// person is someone an export holds.
type person struct {
	Email, Username         string
	Given, Surname, Display string
	Verified                bool
	// Pending is a foreign password hash to be upgraded at first sign-in.
	Pending bool
	// Subject is what the export's applications know them by, "" for
	// nothing this can keep. Their id here is what every token's sub
	// carries, so an application keys its accounts on it: given another,
	// it meets a stranger, and makes a second account for the same person.
	Subject string
	// Handle is the user handle their passkeys were registered under, nil
	// when the export holds none. An authenticator returns it, and either
	// sign-in refuses a passkey whose handle is not the account's.
	Handle []byte
}

// imported is what became of a person.
type imported struct {
	ID  string
	New bool
	// Refused is why they cannot be imported, "" when they were.
	Refused string
	// HandleKept is whether their handle here is the passkeys': without
	// it, their passkeys are refused at sign-in and are not brought.
	HandleKept bool
	// Lost names what of theirs the account here does not carry.
	Lost []string
}

// importPerson finds or makes the person.
//
// The username is unique here as well as the address, and an upsert can name
// only one of the two. An account holding the username under another address
// is somebody else, refused by name; matched by it where either side has no
// address, it is the same person, which a re-run of an export whose people
// have no email must survive. Both once failed the whole import on
// users_org_username_key (0.43).
//
// A person made here takes the subject and the handle when nobody holds
// them. One matched keeps the id they have, and takes the handle only while
// no passkey of theirs here was registered under the one they have (0.44).
func importPerson(ctx context.Context, tx pgx.Tx, orgID string, p person) (imported, error) {
	var holder, holderEmail string
	if p.Username != "" {
		err := tx.QueryRow(ctx, `SELECT id::text, COALESCE(email, '') FROM core.users
			WHERE org_id = $1::uuid AND lower(username) = lower($2)`, orgID, p.Username).Scan(&holder, &holderEmail)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return imported{}, err
		}
	}
	if holder != "" && p.Email != "" && holderEmail != "" && !strings.EqualFold(holderEmail, p.Email) {
		return imported{Refused: fmt.Sprintf("the username %s belongs to another account here, %s", p.Username,
			holderEmail)}, nil
	}
	subject, lostSubject, err := freeSubject(ctx, tx, p.Subject)
	if err != nil {
		return imported{}, err
	}
	handle, lostHandle, err := freeHandle(ctx, tx, p.Handle, "")
	if err != nil {
		return imported{}, err
	}

	var r imported
	if holder != "" && (p.Email == "" || holderEmail == "") {
		// Names fill gaps and never replace what an account already holds.
		r.ID = holder
		if _, err := tx.Exec(ctx, `UPDATE core.users SET
			given_name = COALESCE(given_name, NULLIF($2,'')), surname = COALESCE(surname, NULLIF($3,'')),
			display_name = COALESCE(display_name, NULLIF($4,''))
			WHERE id = $1::uuid`, holder, p.Given, p.Surname, p.Display); err != nil {
			return imported{}, err
		}
	} else if err := tx.QueryRow(ctx, `
		INSERT INTO core.users (id, org_id, email, username, user_handle, email_verified_at, migration_state,
		                        given_name, surname, display_name)
		VALUES (COALESCE($9::uuid, gen_random_uuid()), $1::uuid, NULLIF($2,''), NULLIF($3,''),
		        COALESCE($10, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		                             md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')),
		        CASE WHEN $4 THEN now() ELSE NULL END, CASE WHEN $8 THEN 'pending' ELSE 'none' END,
		        NULLIF($5,''), NULLIF($6,''), NULLIF($7,''))
		-- Matches users_org_email_key exactly: a PARTIAL unique index on
		-- (org_id, lower(email)). The conflict target must mirror the index
		-- expression and its WHERE clause, or PostgreSQL cannot use it and the
		-- import fails on the first existing user -- which is precisely the
		-- re-run an idempotent importer exists to make safe.
		ON CONFLICT (org_id, lower(email)) WHERE email IS NOT NULL
		DO UPDATE SET username = COALESCE(core.users.username, EXCLUDED.username),
		              given_name = COALESCE(core.users.given_name, EXCLUDED.given_name),
		              surname = COALESCE(core.users.surname, EXCLUDED.surname),
		              display_name = COALESCE(core.users.display_name, EXCLUDED.display_name)
		RETURNING id::text, (xmax = 0)`,
		orgID, strings.ToLower(p.Email), p.Username, p.Verified, p.Given, p.Surname, p.Display, p.Pending,
		subject, handle).Scan(&r.ID, &r.New); err != nil {
		return imported{}, err
	}

	if p.Subject != "" && r.ID != p.Subject {
		if lostSubject == "" {
			lostSubject = "an account here already held them"
		}
		r.Lost = append(r.Lost, fmt.Sprintf("subject %s: applications are sent %s for them here (%s), and one "+
			"that keyed an account on the old subject meets them as a stranger", p.Subject, r.ID, lostSubject))
	}
	if len(p.Handle) == 0 {
		return r, nil
	}
	if !r.New && lostHandle == "" {
		// Matched: theirs only if no passkey here holds the one they have.
		handle, lostHandle, err = freeHandle(ctx, tx, p.Handle, r.ID)
		if err != nil {
			return imported{}, err
		}
		if handle != nil {
			if _, err := tx.Exec(ctx, `UPDATE core.users SET user_handle = $2 WHERE id = $1::uuid`,
				r.ID, handle); err != nil {
				return imported{}, err
			}
		}
	}
	var held []byte
	if err := tx.QueryRow(ctx, `SELECT user_handle FROM core.users WHERE id = $1::uuid`, r.ID).Scan(&held); err != nil {
		return imported{}, err
	}
	r.HandleKept = bytes.Equal(held, p.Handle)
	if !r.HandleKept {
		r.Lost = append(r.Lost, "passkeys ("+lostHandle+", and an authenticator returns the handle a passkey "+
			"was registered under, which sign-in refuses unless it is the account's; they register again)")
	}
	return r, nil
}

// freeSubject answers the subject as an id nobody holds, or nil and why not.
// A UUID only, and in the form an id here is written, since sub is compared
// as a string.
func freeSubject(ctx context.Context, tx pgx.Tx, subject string) (*string, string, error) {
	if subject == "" {
		return nil, "", nil
	}
	if u, err := uuid.Parse(subject); err != nil || u.String() != subject {
		return nil, "it is not a UUID in lower case, which an id here is", nil
	}
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE id = $1::uuid)`,
		subject).Scan(&held); err != nil {
		return nil, "", err
	}
	if held {
		return nil, "another account here holds that id", nil
	}
	return &subject, "", nil
}

// freeHandle answers the handle when it may be the person's, or nil and why
// not: one nobody else holds, and for an account already here (userID) one
// that no passkey of theirs was registered under another.
func freeHandle(ctx context.Context, tx pgx.Tx, handle []byte, userID string) ([]byte, string, error) {
	if len(handle) == 0 {
		return nil, "", nil
	}
	if len(handle) > 64 {
		return nil, "their handle is longer than the 64 bytes WebAuthn allows", nil
	}
	var other bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE user_handle = $1
		AND id::text IS DISTINCT FROM NULLIF($2,''))`, handle, userID).Scan(&other); err != nil {
		return nil, "", err
	}
	if other {
		return nil, "another account here holds their handle", nil
	}
	if userID == "" {
		return handle, "", nil
	}
	var registered bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.webauthn_credentials c
		JOIN core.users u ON u.id = c.user_id
		WHERE c.user_id = $1::uuid AND u.user_handle <> $2)`, userID, handle).Scan(&registered); err != nil {
		return nil, "", err
	}
	if registered {
		return nil, "the account here has passkeys of its own, registered under its handle", nil
	}
	return handle, "", nil
}

// groupNamePart is what a group name here may hold (groups_name_shape).
var groupNamePart = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// groupNameOf is a group's name or path as a name here: the segments joined
// by dots, each one's other characters a hyphen; "" for one that does not
// fit.
func groupNameOf(path string) string {
	var parts []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg = strings.Trim(groupNamePart.ReplaceAllString(seg, "-"), "-"); seg != "" {
			parts = append(parts, seg)
		}
	}
	name := strings.Join(parts, ".")
	if len(name) > 64 {
		return ""
	}
	return name
}

// importGroup makes a group, answering whether it is new.
func importGroup(ctx context.Context, tx pgx.Tx, orgID, name, display, description string) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name, description)
		VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (org_id, name) DO NOTHING`, orgID, name, display, description)
	if err != nil {
		return false, fmt.Errorf("importer: creating group %s: %w", name, err)
	}
	return tag.RowsAffected() == 1, nil
}

// importMembership puts the person in the group, answering whether they
// were not in it already.
func importMembership(ctx context.Context, tx pgx.Tx, orgID, group, userID string) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		SELECT id, $3::uuid, org_id FROM core.groups WHERE org_id = $1::uuid AND name = $2
		ON CONFLICT DO NOTHING`, orgID, group, userID)
	if err != nil {
		return false, fmt.Errorf("importer: adding to group %s: %w", group, err)
	}
	return tag.RowsAffected() == 1, nil
}

// importOTP assigns an OTP seed, answering whether it was assigned now, or
// why it cannot be. One held already, imported before or enrolled here since,
// is kept: assigned again, a counter-based token's counter would go back to
// the export's, and the codes pressed since would work a second time.
func importOTP(ctx context.Context, tx pgx.Tx, orgID, userID string, seed []byte, kind string, params mfa.Params,
	last int64, root *keys.RootKey) (bool, string, error) {
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.totp_credentials
		WHERE user_id = $1::uuid AND confirmed_at IS NOT NULL)`, userID).Scan(&held); err != nil {
		return false, "", err
	}
	if held {
		return false, "", nil
	}
	if err := params.Check(); err != nil {
		return false, err.Error(), nil
	}
	if root == nil {
		return false, "sealing a seed needs SIGNARI_ROOT_KEY, which is not loaded", nil
	}
	if _, err := store.AssignOTPToken(ctx, tx, userID, orgID, seed, kind, string(params.Algorithm), params.Digits,
		params.Period, last, root); err != nil {
		return false, "", fmt.Errorf("importer: assigning OTP: %w", err)
	}
	return true, "", nil
}

// passkey is a WebAuthn credential an export holds.
type passkey struct {
	RPID               string
	ID, PublicKey      []byte
	AAGUID             []byte
	SignCount          int64
	Discoverable       bool
	Transports         []string
	Attestation, Label string
}

// importPasskey saves a passkey under the relying party ID it was registered
// with, answering whether it was saved now, or why it cannot be.
func importPasskey(ctx context.Context, tx pgx.Tx, orgID, userID string, k passkey) (bool, string, error) {
	if k.RPID == "" {
		return false, "no relying party ID is recorded for it", nil
	}
	// Checked as sign-in will read it: a key that does not parse here would
	// fail every ceremony.
	if _, err := webauthncose.ParsePublicKey(k.PublicKey); err != nil {
		return false, "its public key is not a COSE key: " + err.Error(), nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.webauthn_credentials WHERE credential_id = $1)`,
		k.ID).Scan(&exists); err != nil {
		return false, "", err
	}
	if exists {
		// Imported before: the import is idempotent, and the counter it holds
		// now is newer than the export's.
		return false, "", nil
	}
	if k.Transports == nil {
		k.Transports = []string{}
	}
	if err := store.SaveCredential(ctx, tx, userID, orgID, k.RPID, k.ID, k.PublicKey, k.AAGUID,
		uint32(max(k.SignCount, 0)), k.Discoverable, false, false, k.Transports, k.Attestation, k.Label); err != nil {
		return false, "", fmt.Errorf("importer: saving a passkey: %w", err)
	}
	return true, "", nil
}

// importLink links the person to a provider registered here, answering
// whether they were linked now, or why not.
func importLink(ctx context.Context, tx pgx.Tx, orgID, slug, userID, subject string) (bool, string, error) {
	already, err := store.LinkSubject(ctx, tx, orgID, slug, userID, subject)
	switch {
	case errors.Is(err, store.ErrIdPLinkTaken) || errors.Is(err, store.ErrIdPLinkPersonElsewhere):
		return false, err.Error(), nil
	case err != nil:
		return false, "", fmt.Errorf("importer: linking to %s: %w", slug, err)
	}
	return !already, "", nil
}

// importNameID keeps the persistent NameID a service provider knows the
// person by, answering whether it was written now, or why it cannot be. A
// service provider keys its accounts on the NameID, so one made afresh here
// is a stranger to it (0.44).
func importNameID(ctx context.Context, tx pgx.Tx, orgID, entityID, userID, nameID string) (bool, string, error) {
	var providerID, format string
	err := tx.QueryRow(ctx, `SELECT id::text, name_id_format FROM core.saml_providers
		WHERE org_id = $1::uuid AND entity_id = $2`, orgID, entityID).Scan(&providerID, &format)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "no such service provider came across", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("importer: finding SAML provider %s: %w", entityID, err)
	}
	if format != "persistent" {
		return false, "it is sent a " + format + " NameID here, not a persistent one", nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO core.saml_name_ids (provider_id, user_id, org_id, name_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4) ON CONFLICT DO NOTHING`, providerID, userID, orgID, nameID)
	if err != nil {
		return false, "", fmt.Errorf("importer: a NameID at %s: %w", entityID, err)
	}
	if tag.RowsAffected() == 1 {
		return true, "", nil
	}
	var held string
	err = tx.QueryRow(ctx, `SELECT name_id FROM core.saml_name_ids WHERE provider_id = $1::uuid
		AND user_id = $2::uuid`, providerID, userID).Scan(&held)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, "another account here is known to it by that NameID", nil
	case err != nil:
		return false, "", err
	case held == nameID:
		return false, "", nil
	default:
		// Signed in through it here since: its account now has the new one.
		return false, "it has known them by another here since, which is kept", nil
	}
}

// importSAMLProvider makes a service provider with its HTTPS ACS URLs,
// answering whether it is new and what of it was skipped.
func importSAMLProvider(ctx context.Context, tx pgx.Tx, orgID, entityID, name, format string, enabled bool,
	acs []string) (bool, []string, error) {
	var usable, skipped []string
	for _, u := range acs {
		if strings.HasPrefix(u, "https://") {
			usable = append(usable, u)
		} else {
			skipped = append(skipped, fmt.Sprintf("SAML provider %s ACS %s (it carries a signed assertion and must "+
				"be https)", entityID, u))
		}
	}
	if len(usable) == 0 {
		return false, append(skipped, "SAML provider "+entityID+" (no https ACS URL)"), nil
	}
	var id string
	var created bool
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.saml_providers (org_id, entity_id, display_name, name_id_format, enabled)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (org_id, entity_id) DO UPDATE SET display_name = core.saml_providers.display_name
		RETURNING id::text, (xmax = 0)`, orgID, entityID, name, format, enabled).Scan(&id, &created); err != nil {
		if strings.Contains(err.Error(), "saml_providers_entity_id_key") {
			return false, append(skipped, "SAML provider "+entityID+" (another organisation registered that "+
				"entity ID)"), nil
		}
		return false, nil, fmt.Errorf("importer: SAML provider %s: %w", entityID, err)
	}
	for i, u := range usable {
		if _, err := tx.Exec(ctx, `INSERT INTO core.saml_acs_urls (provider_id, url, binding, is_default)
			VALUES ($1::uuid, $2, 'HTTP-POST', $3) ON CONFLICT DO NOTHING`, id, u, i == 0 && created); err != nil {
			return false, nil, fmt.Errorf("importer: SAML provider %s ACS %s: %w", entityID, u, err)
		}
	}
	return created, skipped, nil
}

// importClient makes an OpenID Connect client with the secret it holds,
// hashed, and its redirect URIs, answering whether it is new.
func importClient(ctx context.Context, tx pgx.Tx, orgID, clientID, name, secret string, public, enabled bool,
	grants, redirects []string, hasher *passwords.Hasher, res *Result) (bool, error) {
	kind := "confidential"
	if public {
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
	if secret != "" {
		h, herr := hasher.Hash(ctx, secret)
		if herr != nil {
			return false, fmt.Errorf("importer: hashing the secret for %s: %w", clientID, herr)
		}
		secretHash = h
	}
	if name == "" {
		name = clientID
	}
	// PKCE required, as for every client created here. This once required it
	// only of public clients, so every imported confidential client accepted
	// an authorization request with no challenge. The ones that may need an
	// opt-out are listed, not left to fail silently in either direction.
	tag, err := tx.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, enabled, grant_types, scopes, require_pkce)
		VALUES ($1, $2::uuid, $7, $3, $4, $5, $6,
		        ARRAY['openid','profile','email'], true)
		ON CONFLICT (client_id) DO NOTHING`,
		clientID, orgID, kind, secretHash, enabled, grants, name)
	if err != nil {
		return false, fmt.Errorf("importer: creating client %s: %w", clientID, err)
	}
	created := tag.RowsAffected() == 1
	if created && !public && slices.Contains(grants, "authorization_code") {
		res.ClientsNowRequiringPKCE = append(res.ClientsNowRequiringPKCE, clientID)
	}
	for _, u := range redirects {
		// An import brings somebody else's registrations, and other products
		// permit shapes we do not: wildcards, and redirect URIs carrying
		// response parameters.
		//
		// SKIPPED AND REPORTED rather than fatal. A migration that dies on
		// one bad URI out of four hundred is a migration nobody finishes,
		// and the operator needs the list of what did not come across --
		// which is exactly what ClientsSkipped is.
		if verr := clients.ValidateRedirectURI(u); verr != nil {
			res.ClientsSkipped = append(res.ClientsSkipped, clientID+" redirect "+u+" ("+verr.Error()+")")
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`, clientID, u); err != nil {
			return false, fmt.Errorf("importer: redirect for %s: %w", clientID, err)
		}
	}
	return created, nil
}

// providerRegistered reports whether the organisation has a provider of that
// slug, remembered per import.
func providerRegistered(ctx context.Context, tx pgx.Tx, orgID, slug string, seen map[string]bool) (bool, error) {
	if known, ok := seen[slug]; ok {
		return known, nil
	}
	var known bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.identity_providers
		WHERE org_id = $1::uuid AND slug = $2)`, orgID, slug).Scan(&known); err != nil {
		return false, fmt.Errorf("importer: looking for provider %s: %w", slug, err)
	}
	seen[slug] = known
	return known, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
