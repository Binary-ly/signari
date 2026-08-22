package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/passwords"
)

// The LDAP write path, RFC 4511 §4.6–§4.9, against the real store.
//
// # Why this is a separate type from LDAPAuthenticator
//
// They read the same rows and mean opposite things. An authenticator answers
// "is this person who they say they are" and is reachable by anybody who can
// open the port; a writer rewrites the directory and is reachable only by a
// named group. Hanging both off one type would make it very easy to hand a
// write method to something that only needed to verify a password.
//
// # Every write goes through the same paths as every other write
//
// Passwords through the same policy and the same Argon2 parameters as the
// sign-in form and the CLI; deletions through the same cascade. An LDAP front
// end with its own quiet write path is a way around every control the rest of
// the product has -- which is exactly the sentence the authenticator's comment
// makes about credentials, and it was two-thirds true there until somebody
// checked.

// LDAPWriter implements ldapd.Writer against the database.
type LDAPWriter struct {
	db     ldapWriteDB
	hasher *passwords.Hasher
	orgID  string
	log    logger
	// policy is the SAME value the sign-in form and the sign-up page use --
	// passwords.PolicyFromEnv, held on the Server. Passed in rather than built
	// here, because a second construction of "the policy" is a second answer to
	// what a password may be, and the weaker of the two is the one that decides.
	policy passwords.Policy
}

// ldapWriteDB is what a writer needs: a transaction, and reads outside one.
type ldapWriteDB interface {
	Begin(context.Context) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NewLDAPWriter builds the write half of the directory.
func NewLDAPWriter(db ldapWriteDB, hasher *passwords.Hasher, policy passwords.Policy,
	orgID string, log logger) *LDAPWriter {

	return &LDAPWriter{db: db, hasher: hasher, policy: policy, orgID: orgID, log: log}
}

// Create adds a user, §4.7.
func (w *LDAPWriter) Create(ctx context.Context, actor string, e *ldapd.NewEntry) error {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// §4.7: "The entry named in the entry field of the AddRequest MUST NOT exist
	// for the AddRequest to succeed."
	//
	// The uniqueness guard is the INSERT's own unique index, not this check --
	// see the conflict handling below. This exists to give the common case the
	// right result code without waiting for a constraint to fire.
	if taken, err := w.nameTaken(ctx, tx, e.Username, ""); err != nil {
		return err
	} else if taken {
		return ldapd.ErrEntryExists
	}
	// An email is a second name in this directory: `Lookup` matches on username
	// OR email, so two accounts sharing an address make a bind ambiguous and the
	// one that wins depends on row order. Refused here rather than discovered
	// later by somebody who cannot sign in.
	if e.Email != "" {
		if taken, err := w.emailTaken(ctx, tx, e.Email, ""); err != nil {
			return err
		} else if taken {
			return fmt.Errorf("%w: another entry already has the mail address %s",
				ldapd.ErrConstraint, e.Email)
		}
	}

	var hash string
	if e.Password != "" {
		h, perr := w.hashPassword(ctx, e.Password, e.Username, e.Email)
		if perr != nil {
			return perr
		}
		hash = h
	}

	var userID string
	err = tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, username, email, display_name, surname,
		                        given_name, user_handle, status)
		VALUES ($1::uuid, $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''),
		        NULLIF($6,''),
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		        'active')
		RETURNING id::text`,
		w.orgID, e.Username, e.Email, e.CommonName, e.Surname, e.GivenName).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err) {
			// The race the check above cannot close: two Adds for the same name,
			// arriving together. The index is the guard; this turns its error into
			// the result code §4.7 specifies.
			return ldapd.ErrEntryExists
		}
		return fmt.Errorf("creating the entry: %w", err)
	}

	if hash != "" {
		// org_id as well as user_id. It is NOT NULL and it is what the tenant
		// isolation policy on this table reads -- a row without it is refused by
		// the schema, which is how this was found: the unit tests drive a fake
		// writer, so the first INSERT that ever ran against a real database was
		// the one in the walkthrough.
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
			VALUES ($1::uuid, $2::uuid, $3, 'argon2id', true)`,
			userID, w.orgID, hash); err != nil {
			return fmt.Errorf("storing the password: %w", err)
		}
	}

	// Audited INSIDE the transaction. A directory write that is not in the trail
	// is one nobody can answer for, and committing the change while the record of
	// it failed would be exactly that.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "ldap.entry_created", OrgID: w.orgID, SubjectID: userID,
		Detail: map[string]any{
			"via": "ldap", "actor": actor, "uid": e.Username,
			"password_set": hash != "",
		},
	}); err != nil {
		return fmt.Errorf("auditing the entry creation: %w", err)
	}
	// A password set AT CREATION gets the same event as one set later.
	//
	// It was originally only a detail on the creation event, which meant "show
	// me every password set over LDAP" -- the query an investigation actually
	// runs -- missed exactly the accounts whose password was chosen by somebody
	// other than their owner from the very first moment.
	if hash != "" {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "ldap.password_set", OrgID: w.orgID, SubjectID: userID,
			Detail: map[string]any{
				"via": "ldap", "actor": actor, "uid": e.Username,
				"at_creation": true, "removed": false,
			},
		}); err != nil {
			return fmt.Errorf("auditing the password: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Update applies a resolved Modify, §4.6.
//
// One statement for the row and one for the credential, in one transaction.
// §4.6: "The entire list of modifications MUST be performed in the order they
// are listed as a single atomic operation ... the client may expect that no
// modifications of the DIT have been performed if the Modify Response received
// indicates any sort of error."
func (w *LDAPWriter) Update(ctx context.Context, actor, username string, u *ldapd.Update) error {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID, currentEmail string
	err = tx.QueryRow(ctx, `
		SELECT id::text, COALESCE(email,'') FROM core.users
		WHERE org_id = $1::uuid AND status = 'active'
		  AND (lower(username) = lower($2) OR lower(email) = lower($2))`,
		w.orgID, username).Scan(&userID, &currentEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapd.ErrNoSuchEntry
	}
	if err != nil {
		return err
	}

	if u.Email != nil && *u.Email != "" && !strings.EqualFold(*u.Email, currentEmail) {
		if taken, err := w.emailTaken(ctx, tx, *u.Email, userID); err != nil {
			return err
		} else if taken {
			return fmt.Errorf("%w: another entry already has the mail address %s",
				ldapd.ErrConstraint, *u.Email)
		}
	}

	// COALESCE against the parameter's own NULL, so one statement expresses
	// "change these, leave the rest". Building the SET clause by string
	// concatenation from whichever fields are non-nil is the other way to write
	// this, and it is how a column name reaches SQL from a request.
	if _, err := tx.Exec(ctx, `
		UPDATE core.users SET
			email        = CASE WHEN $2::boolean THEN NULLIF($3,'')  ELSE email        END,
			display_name = CASE WHEN $4::boolean THEN NULLIF($5,'')  ELSE display_name END,
			surname      = CASE WHEN $6::boolean THEN NULLIF($7,'')  ELSE surname      END,
			given_name   = CASE WHEN $8::boolean THEN NULLIF($9,'')  ELSE given_name   END,
			updated_at   = now()
		WHERE id = $1::uuid`,
		userID,
		u.Email != nil, deref(u.Email),
		u.CommonName != nil, deref(u.CommonName),
		u.Surname != nil, deref(u.Surname),
		u.GivenName != nil, deref(u.GivenName),
	); err != nil {
		return fmt.Errorf("modifying the entry: %w", err)
	}
	// displayName and cn both exist in the schema and there is one column. cn is
	// the MUST attribute and the one a directory client displays, so it wins;
	// displayName is applied only when cn was not also in the same request.
	if u.DisplayName != nil && u.CommonName == nil {
		if _, err := tx.Exec(ctx,
			`UPDATE core.users SET display_name = NULLIF($2,''), updated_at = now()
			 WHERE id = $1::uuid`, userID, *u.DisplayName); err != nil {
			return fmt.Errorf("modifying the entry: %w", err)
		}
	}

	passwordChanged := false
	if u.Password != nil {
		if *u.Password == "" {
			// `delete userPassword` -- the credential goes, the account stays. Not
			// the same as a password of zero length, which would be an account
			// anybody can bind to.
			if _, err := tx.Exec(ctx,
				`DELETE FROM core.password_credentials WHERE user_id = $1::uuid`,
				userID); err != nil {
				return fmt.Errorf("removing the password: %w", err)
			}
		} else {
			email := currentEmail
			if u.Email != nil {
				email = *u.Email
			}
			hash, perr := w.hashPassword(ctx, *u.Password, username, email)
			if perr != nil {
				return perr
			}
			// The reset clears everything the OLD password carried -- the throttle
			// counters, the must-change flag, the breach-check stamp. That is the
			// same set store.SetPassword clears, and for the same reason: leaving
			// any of them behind attaches a previous password's history to a new
			// one, most visibly as a user who changes their password as instructed
			// and is asked to do it again.
			if _, err := tx.Exec(ctx, `
				INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm, is_current)
				VALUES ($1::uuid, $2::uuid, $3, 'argon2id', true)
				ON CONFLICT (user_id) DO UPDATE
				SET hash = EXCLUDED.hash, algorithm = 'argon2id', is_current = true,
				    updated_at = now(), failed_attempts = 0, throttled_until = NULL,
				    last_failure_at = NULL, must_change = false,
				    must_change_reason = NULL, last_breach_check = NULL`,
				userID, w.orgID, hash); err != nil {
				return fmt.Errorf("storing the password: %w", err)
			}
		}
		passwordChanged = true
	}

	// A password set through this path is recorded as its own event, not folded
	// into "the entry was modified". Somebody with directory write access can set
	// any password and then bind as that person, which is the most consequential
	// thing this interface can do and the thing an investigation looks for.
	if passwordChanged {
		if err := audit.Write(ctx, tx, audit.Event{
			Type: "ldap.password_set", OrgID: w.orgID, SubjectID: userID,
			Detail: map[string]any{
				"via": "ldap", "actor": actor, "uid": username,
				"removed": *u.Password == "",
			},
		}); err != nil {
			return fmt.Errorf("auditing the password change: %w", err)
		}
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "ldap.entry_modified", OrgID: w.orgID, SubjectID: userID,
		Detail: map[string]any{
			"via": "ldap", "actor": actor, "uid": username,
			"attributes": changedAttrs(u),
		},
	}); err != nil {
		return fmt.Errorf("auditing the modification: %w", err)
	}
	return tx.Commit(ctx)
}

// Remove deletes a user, §4.8.
//
// It DELETES. It does not deactivate.
//
// A directory Delete that quietly deactivates is the failure this whole file is
// written against: the client asked for the entry to be gone, a subsequent
// search would not find it, and the row would still be there. Deactivation is
// available through `signari` and is a different request.
//
// Note what this is NOT: `signari erase subject`. Deleting the row removes it
// and everything that cascades from it; it does not destroy the subject's
// data-encryption key, so ciphertext already written to backups stays readable.
// Crypto-shredding is a separate, deliberate act -- see docs/erasure.md.
func (w *LDAPWriter) Remove(ctx context.Context, actor, username string) error {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid
		  AND (lower(username) = lower($2) OR lower(email) = lower($2))`,
		w.orgID, username).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapd.ErrNoSuchEntry
	}
	if err != nil {
		return err
	}

	// Audited BEFORE the delete, in the same transaction. Afterwards there is no
	// row for SubjectID to point at, and an audit trail whose most destructive
	// event names nobody is the one you cannot read later.
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "ldap.entry_deleted", OrgID: w.orgID, SubjectID: userID,
		Detail: map[string]any{"via": "ldap", "actor": actor, "uid": username},
	}); err != nil {
		return fmt.Errorf("auditing the deletion: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM core.users WHERE id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("deleting the entry: %w", err)
	}
	w.log.Warn("ldap deleted a user", "uid", username, "actor", actor)
	return tx.Commit(ctx)
}

// Rename changes the naming attribute, §4.9.
func (w *LDAPWriter) Rename(ctx context.Context, actor, from, to string) error {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM core.users
		WHERE org_id = $1::uuid AND lower(username) = lower($2)`,
		w.orgID, from).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapd.ErrNoSuchEntry
	}
	if err != nil {
		return err
	}
	if taken, err := w.nameTaken(ctx, tx, to, userID); err != nil {
		return err
	} else if taken {
		return ldapd.ErrEntryExists
	}

	if _, err := tx.Exec(ctx,
		`UPDATE core.users SET username = $2, updated_at = now() WHERE id = $1::uuid`,
		userID, to); err != nil {
		if isUniqueViolation(err) {
			return ldapd.ErrEntryExists
		}
		return fmt.Errorf("renaming the entry: %w", err)
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "ldap.entry_renamed", OrgID: w.orgID, SubjectID: userID,
		Detail: map[string]any{"via": "ldap", "actor": actor, "from": from, "to": to},
	}); err != nil {
		return fmt.Errorf("auditing the rename: %w", err)
	}
	return tx.Commit(ctx)
}

// hashPassword runs the organisation's policy and then Argon2.
//
// The policy first, always. A directory write is the one path where a password
// arrives without a person in front of a form to be told what is wrong with it,
// which makes it the path most likely to seed an estate with weak credentials --
// so it is held to exactly the same rules as the sign-in form rather than
// trusted because an administrator sent it.
func (w *LDAPWriter) hashPassword(ctx context.Context, password, username, email string) (string, error) {
	// `identity` is what the policy compares against for the contextual rule -- a
	// password containing the person's own name or address is guessable by
	// anybody who knows who they are. The email when there is one, because that
	// is the more identifying of the two.
	identity := email
	if identity == "" {
		identity = username
	}
	res, err := w.policy.Check(ctx, password, identity, nil, w.hasher)
	if err != nil {
		// ErrConstraint, so the protocol layer answers constraintViolation(19) --
		// which tells a provisioning run to fix the data rather than to retry.
		return "", fmt.Errorf("%w: %s", ldapd.ErrConstraint, err.Error())
	}
	if w.policy.Breach != nil && !res.BreachCheckRan {
		// A configured control that did not run. Logged loudly rather than
		// swallowed, the same as the sign-up path does: a check that quietly
		// stopped running is worse than one never configured.
		w.log.Warn("the breach check did not run for a password set over LDAP",
			"uid", username)
	}
	hash, err := w.hasher.Hash(ctx, password)
	if err != nil {
		return "", fmt.Errorf("hashing the password: %w", err)
	}
	return hash, nil
}

func (w *LDAPWriter) nameTaken(ctx context.Context, q pgx.Tx, name, exceptID string) (bool, error) {
	var n int
	err := q.QueryRow(ctx, `
		SELECT count(*) FROM core.users
		WHERE org_id = $1::uuid
		  AND (lower(username) = lower($2) OR lower(email) = lower($2))
		  AND ($3 = '' OR id <> $3::uuid)`, w.orgID, name, exceptID).Scan(&n)
	return n > 0, err
}

func (w *LDAPWriter) emailTaken(ctx context.Context, q pgx.Tx, email, exceptID string) (bool, error) {
	var n int
	err := q.QueryRow(ctx, `
		SELECT count(*) FROM core.users
		WHERE org_id = $1::uuid AND lower(email) = lower($2)
		  AND ($3 = '' OR id <> $3::uuid)`, w.orgID, email, exceptID).Scan(&n)
	return n > 0, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// changedAttrs names what a modification touched, for the audit detail.
//
// Names only. The VALUES are deliberately absent: a mail address is personal
// data and the audit detail column is explicitly non-personal, and a password
// obviously does not belong there either.
func changedAttrs(u *ldapd.Update) []string {
	var out []string
	for name, set := range map[string]bool{
		"mail": u.Email != nil, "cn": u.CommonName != nil,
		"sn": u.Surname != nil, "givenName": u.GivenName != nil,
		"displayName": u.DisplayName != nil, "userPassword": u.Password != nil,
	} {
		if set {
			out = append(out, name)
		}
	}
	return out
}

// isUniqueViolation recognises PostgreSQL's 23505.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "23505")
}
