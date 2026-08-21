package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/scim"
)

// deactivatedStatus is the value core.users actually allows.
//
// Its check constraint permits active | deactivated | locked. The first version
// of this file wrote "inactive", which is the obvious English word and not one
// of the three -- so every SCIM deactivation failed with a constraint violation
// and returned 500. An upstream retries a 500 indefinitely while the person it
// was trying to deprovision stays signed in.
const deactivatedStatus = "deactivated"

// SCIMSource is a configured upstream provisioner.
type SCIMSource struct {
	ID          string
	OrgID       string
	Slug        string
	DisplayName string
	TokenHash   []byte
	OnDelete    string
}

// SCIMUser is one provisioned person.
type SCIMUser struct {
	ResourceID  string
	ExternalID  string
	UserID      string
	UserName    string
	DisplayName string
	Email       string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SCIMConflictError reports a uniqueness violation, so the handler can answer
// 409 with scimType "uniqueness" instead of 500.
//
// The distinction is operational, not cosmetic: an upstream retries a 500
// forever and stops on a 409.
type SCIMConflictError struct{ Detail string }

func (e *SCIMConflictError) Error() string { return e.Detail }

// FindSCIMSourceByToken resolves a bearer token hash to its source.
func FindSCIMSourceByToken(ctx context.Context, db *pgxpool.Pool, hash []byte) (
	*SCIMSource, error) {

	s := &SCIMSource{}
	err := db.QueryRow(ctx, `
		UPDATE core.scim_sources SET last_seen_at = now()
		WHERE token_hash = $1 AND enabled
		RETURNING id::text, org_id::text, slug, display_name, token_hash, on_delete`,
		hash).Scan(&s.ID, &s.OrgID, &s.Slug, &s.DisplayName, &s.TokenHash, &s.OnDelete)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListSCIMUsers returns a page, and the total the page was drawn from.
//
// startIndex is ONE-based, as SCIM requires. The offset conversion happens here,
// once, rather than in each caller -- an off-by-one in this arithmetic drops the
// first user of every page and looks like an intermittent sync failure.
func ListSCIMUsers(ctx context.Context, db *pgxpool.Pool, sourceID, userNameFilter string,
	startIndex, count int) ([]SCIMUser, int, error) {

	if startIndex < 1 {
		startIndex = 1
	}
	offset := startIndex - 1

	var total int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FROM core.scim_source_links l
		WHERE l.source_id = $1::uuid
		  AND ($2 = '' OR lower(l.user_name) = lower($2))`,
		sourceID, userNameFilter).Scan(&total); err != nil {
		return nil, 0, err
	}

	// count=0 is a legitimate SCIM request meaning "tell me the total, send no
	// resources". Answering it with a page of results is wrong and answering it
	// with an error breaks the discovery step some upstreams perform first.
	if count == 0 {
		return nil, total, nil
	}

	rows, err := db.Query(ctx, `
		SELECT l.resource_id::text, l.external_id, l.user_id::text, l.user_name,
		       l.display_name, COALESCE(u.email,''),
		       u.status = 'active', l.created_at, l.updated_at
		FROM core.scim_source_links l
		JOIN core.users u ON u.id = l.user_id
		WHERE l.source_id = $1::uuid
		  AND ($2 = '' OR lower(l.user_name) = lower($2))
		ORDER BY l.created_at, l.external_id
		LIMIT $3 OFFSET $4`, sourceID, userNameFilter, count, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []SCIMUser
	for rows.Next() {
		var u SCIMUser
		if err := rows.Scan(&u.ResourceID, &u.ExternalID, &u.UserID, &u.UserName,
			&u.DisplayName, &u.Email, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// GetSCIMUser reads one resource by the id this engine issued.
func GetSCIMUser(ctx context.Context, db *pgxpool.Pool, sourceID, resourceID string) (
	SCIMUser, error) {

	var u SCIMUser
	err := db.QueryRow(ctx, `
		SELECT l.resource_id::text, l.external_id, l.user_id::text, l.user_name,
		       l.display_name, COALESCE(u.email,''),
		       u.status = 'active', l.created_at, l.updated_at
		FROM core.scim_source_links l
		JOIN core.users u ON u.id = l.user_id
		WHERE l.source_id = $1::uuid AND l.resource_id = $2::uuid`,
		sourceID, resourceID).
		Scan(&u.ResourceID, &u.ExternalID, &u.UserID, &u.UserName, &u.DisplayName,
			&u.Email, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// UpsertSCIMUser creates a person, or returns the one already provisioned.
//
// Keyed on (source, external_id). A repeated create with the same externalId is
// the SAME person arriving twice, not a second person: upstreams retry, and a
// create that is not idempotent turns one retry into two accounts.
func UpsertSCIMUser(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	in scim.User) (SCIMUser, error) {

	var out SCIMUser
	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	email := primaryEmail(in)
	display := strings.TrimSpace(in.DisplayName)
	if display == "" {
		display = strings.TrimSpace(in.UserName)
	}

	// Already provisioned by this source?
	existing, err := scimLinkByExternalID(ctx, tx, src.ID, in.ExternalID)
	if err == nil {
		// Idempotent: update what changed and return it as it now stands.
		if err := applyUserFields(ctx, tx, existing.UserID, &email, boolPtr(in.Active)); err != nil {
			return out, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE core.scim_source_links
			SET user_name = $3, display_name = $4, updated_at = now()
			WHERE source_id = $1::uuid AND external_id = $2`,
			src.ID, in.ExternalID, in.UserName, display); err != nil {
			return out, err
		}
		if err := tx.Commit(ctx); err != nil {
			return out, err
		}
		return GetSCIMUser(ctx, db, src.ID, existing.ResourceID)
	} else if err != pgx.ErrNoRows {
		return out, err
	}

	// A local account with this address may already exist -- somebody who signed
	// up before provisioning was turned on. Adopted rather than duplicated, but
	// ONLY within this organisation and only when nothing else claims it.
	var userID string
	if email != "" {
		err = tx.QueryRow(ctx, `
			SELECT id::text FROM core.users WHERE org_id = $1::uuid AND lower(email) = lower($2)`,
			src.OrgID, email).Scan(&userID)
		if err != nil && err != pgx.ErrNoRows {
			return out, err
		}
	}

	if userID == "" {
		status := "active"
		if !in.Active {
			status = deactivatedStatus
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO core.users (org_id, username, email, status, user_handle)
			VALUES ($1::uuid, NULLIF($2,''), NULLIF($3,''), $4,
			        -- The 64-byte WebAuthn handle, generated the same way
			        -- CreateUserFromExternal does. It is NOT NULL and has no
			        -- default, so every insert site must produce one; a second
			        -- convention here would be a second thing to get wrong.
			        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
			RETURNING id::text`,
			src.OrgID, in.UserName, email, status).Scan(&userID); err != nil {
			if isUniqueViolation(err) {
				return out, &SCIMConflictError{
					Detail: fmt.Sprintf("a user with userName %q already exists", in.UserName)}
			}
			return out, err
		}
	} else if err := applyUserFields(ctx, tx, userID, nil, boolPtr(in.Active)); err != nil {
		return out, err
	}

	var resourceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.scim_source_links
			(source_id, external_id, user_id, user_name, display_name)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5)
		RETURNING resource_id::text`,
		src.ID, in.ExternalID, userID, in.UserName, display).Scan(&resourceID); err != nil {
		if isUniqueViolation(err) {
			return out, &SCIMConflictError{
				Detail: fmt.Sprintf("userName %q is already provisioned by this source",
					in.UserName)}
		}
		return out, err
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return GetSCIMUser(ctx, db, src.ID, resourceID)
}

// ReplaceSCIMUser applies a PUT: every attribute takes the value given.
func ReplaceSCIMUser(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string, in scim.User) (SCIMUser, error) {

	var out SCIMUser
	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	link, err := scimLinkByResourceID(ctx, tx, src.ID, resourceID)
	if err != nil {
		return out, err
	}

	email := primaryEmail(in)
	display := strings.TrimSpace(in.DisplayName)
	if err := applyUserFields(ctx, tx, link.UserID, &email, boolPtr(in.Active)); err != nil {
		return out, err
	}
	// PUT replaces, so the name is written even when it was sent empty: that is
	// what "replace" means, and quietly keeping the old one would make a PUT
	// behave like a PATCH.
	if _, err := tx.Exec(ctx, `
		UPDATE core.scim_source_links
		SET user_name = COALESCE(NULLIF($3,''), user_name),
		    display_name = $4, updated_at = now()
		WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
		src.ID, resourceID, in.UserName, display); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return GetSCIMUser(ctx, db, src.ID, resourceID)
}

// PatchSCIMUser applies the subset of changes a PATCH asked for.
//
// Only what was mentioned. The pointers in UserPatch carry that distinction,
// and losing it here would let a PATCH of the display name clear the address.
func PatchSCIMUser(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string, p *scim.UserPatch) (SCIMUser, error) {

	var out SCIMUser
	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	link, err := scimLinkByResourceID(ctx, tx, src.ID, resourceID)
	if err != nil {
		return out, err
	}
	if err := applyUserFields(ctx, tx, link.UserID, p.Email, p.Active); err != nil {
		return out, err
	}
	// Only what was mentioned: COALESCE leaves the other column untouched when
	// its pointer was nil, which is the whole reason those fields are pointers.
	if p.UserName != nil || p.DisplayName != nil {
		var un, dn *string = p.UserName, p.DisplayName
		if _, err := tx.Exec(ctx, `
			UPDATE core.scim_source_links
			SET user_name = COALESCE($3, user_name),
			    display_name = COALESCE($4, display_name),
			    updated_at = now()
			WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
			src.ID, resourceID, un, dn); err != nil {
			return out, err
		}
	}

	// Deactivation ends sessions. A SCIM deactivation that leaves a live session
	// running means the person who was just deprovisioned stays signed in until
	// their session expires, which is the whole point of deprovisioning.
	if p.Active != nil && !*p.Active {
		if _, err := tx.Exec(ctx,
			`UPDATE core.sessions SET revoked_at = now(),
			        revocation_reason = 'user_deactivated'
			 WHERE user_id = $1::uuid AND revoked_at IS NULL`, link.UserID); err != nil {
			return out, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return GetSCIMUser(ctx, db, src.ID, resourceID)
}

// DeleteSCIMUser handles a DELETE according to the source's policy.
func DeleteSCIMUser(ctx context.Context, db *pgxpool.Pool, src *SCIMSource,
	resourceID string) (SCIMUser, error) {

	var out SCIMUser
	// Read it first so the caller can audit who was affected -- afterwards, the
	// row may not exist to ask about.
	u, err := GetSCIMUser(ctx, db, src.ID, resourceID)
	if err != nil {
		return out, err
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if src.OnDelete == "delete" {
		if _, err := tx.Exec(ctx, `DELETE FROM core.users WHERE id = $1::uuid`,
			u.UserID); err != nil {
			return out, err
		}
	} else {
		f := false
		if err := applyUserFields(ctx, tx, u.UserID, nil, &f); err != nil {
			return out, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE core.sessions SET revoked_at = now(),
			        revocation_reason = 'user_deactivated'
			 WHERE user_id = $1::uuid AND revoked_at IS NULL`, u.UserID); err != nil {
			return out, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	u.Active = false
	return u, nil
}

// applyUserFields writes only the fields that were given.
func applyUserFields(ctx context.Context, tx pgx.Tx, userID string,
	email *string, active *bool) error {

	if email != nil && *email != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE core.users SET email = $2 WHERE id = $1::uuid`,
			userID, *email); err != nil {
			return err
		}
	}
	if active != nil {
		status := deactivatedStatus
		if *active {
			status = "active"
		}
		if _, err := tx.Exec(ctx,
			`UPDATE core.users SET status = $2 WHERE id = $1::uuid`,
			userID, status); err != nil {
			return err
		}
	}
	return nil
}

type scimLink struct {
	ResourceID string
	ExternalID string
	UserID     string
}

func scimLinkByExternalID(ctx context.Context, tx pgx.Tx, sourceID, externalID string) (
	scimLink, error) {

	var l scimLink
	err := tx.QueryRow(ctx, `
		SELECT resource_id::text, external_id, user_id::text
		FROM core.scim_source_links
		WHERE source_id = $1::uuid AND external_id = $2`,
		sourceID, externalID).Scan(&l.ResourceID, &l.ExternalID, &l.UserID)
	return l, err
}

func scimLinkByResourceID(ctx context.Context, tx pgx.Tx, sourceID, resourceID string) (
	scimLink, error) {

	var l scimLink
	err := tx.QueryRow(ctx, `
		SELECT resource_id::text, external_id, user_id::text
		FROM core.scim_source_links
		WHERE source_id = $1::uuid AND resource_id = $2::uuid`,
		sourceID, resourceID).Scan(&l.ResourceID, &l.ExternalID, &l.UserID)
	return l, err
}

// primaryEmail picks the address SCIM says is primary, or the first one.
func primaryEmail(u scim.User) string {
	for _, e := range u.Emails {
		if e.Primary && strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	for _, e := range u.Emails {
		if strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	// Many upstreams put the address in userName and send no emails array.
	if strings.Contains(u.UserName, "@") {
		return strings.TrimSpace(u.UserName)
	}
	return ""
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key")
}

func boolPtr(b bool) *bool { return &b }
