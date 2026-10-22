package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
)

// Invitations, and open self-signup.
//
// # The token is never stored
//
// Only its SHA-256 is. An invitation is a credential -- it creates an account
// in the organisation -- and a database read must not yield working ones, for
// exactly the reason it must not yield working passwords.
//
// # Claiming is atomic
//
// "Check whether it is used, then mark it used" is two statements and a race:
// two people following the same forwarded link at the same moment both pass the
// check. The claim is therefore a single UPDATE that both filters and marks,
// and the row it returns is the proof that this caller got it and nobody else
// did.

// ErrInvitationNotUsable covers every reason a token will not work.
//
// Deliberately one error. Distinguishing "no such invitation" from "already
// used" from "expired" turns the endpoint into an oracle for guessing tokens,
// and none of the distinctions help the person holding a link that does not
// work -- they need to ask for a new one either way.
var ErrInvitationNotUsable = errors.New("that invitation is not valid")

// Invitation is a claimed invitation.
type Invitation struct {
	ID     string
	OrgID  string
	Email  string
	Groups []string
}

// NewInvitationToken mints a token and returns it with its hash.
//
// 32 bytes from crypto/rand. The token is returned once, to be put in a link,
// and is unrecoverable afterwards.
func NewInvitationToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// InvitationSpec is what an invitation is made with.
type InvitationSpec struct {
	OrgID, Email string
	Groups       []string
	TTL          time.Duration
	// CreatedBy is the person who made it, where a person did.
	CreatedBy string
	// Send mails the link to Email through the outbox (NoticeInvitation), the
	// token minted as it goes out (MintInvitationToken), so it is never shown
	// and never sits in the outbox (5.18).
	Send bool
}

// ErrInvitationSendNeedsAddress is a Send with no Email: an unbound link goes
// to whoever is handed it, so there is nobody to mail it to.
var ErrInvitationSendNeedsAddress = errors.New("an invitation is mailed only to the address it is bound to")

// MaxInvitationTTL bounds how long one stays good: an invitation that
// outlives the reason it was sent is a standing way in.
const MaxInvitationTTL = 90 * 24 * time.Hour

// NewInvitation writes one in tx, for the CLI and the Admin API alike, and
// returns its id and expiry, and its token -- empty when it is Sent, since the
// mail carries the only one. A Sent invitation holds the hash of a token nobody
// has until then, so it opens nothing before the mail goes out.
func NewInvitation(ctx context.Context, tx pgx.Tx, spec InvitationSpec) (id, token string, expires time.Time, err error) {
	if spec.TTL <= 0 {
		spec.TTL = 7 * 24 * time.Hour
	}
	if spec.TTL > MaxInvitationTTL {
		return "", "", time.Time{}, fmt.Errorf("an invitation lasts at most %s", MaxInvitationTTL)
	}
	email := strings.ToLower(strings.TrimSpace(spec.Email))
	if spec.Send && email == "" {
		return "", "", time.Time{}, ErrInvitationSendNeedsAddress
	}
	token, hash, err := NewInvitationToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	if spec.Groups == nil {
		spec.Groups = []string{}
	}
	var by any
	if spec.CreatedBy != "" {
		by = spec.CreatedBy
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO core.invitations
			(org_id, token_hash, email, grant_groups, expires_at, created_by)
		VALUES ($1::uuid, $2, NULLIF($3,''), $4, now() + make_interval(secs => $5), $6::uuid)
		RETURNING id::text, expires_at`,
		spec.OrgID, hash, email, spec.Groups, int(spec.TTL.Seconds()), by).Scan(&id, &expires); err != nil {
		return "", "", time.Time{}, err
	}
	if !spec.Send {
		return id, token, expires, nil
	}
	if err := EnqueueAccountNotice(ctx, tx, AccountNotice{Notice: NoticeInvitation, LinkID: id}); err != nil {
		return "", "", time.Time{}, err
	}
	return id, "", expires, nil
}

// MintInvitationToken makes the token a mailed invitation's link carries, as
// the mail goes out, while the invitation is still open. Each delivery makes a
// new one, so a mail sent again by a retry carries a link that works and the
// earlier one stops: the newest invitation mail is the one to use.
func MintInvitationToken(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) (token, email, orgID string, expires time.Time, err error) {
	canonical, ok := CanonicalUUID(id)
	if !ok {
		return "", "", "", time.Time{}, ErrInvitationNotUsable
	}
	token, hash, err := NewInvitationToken()
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	err = db.QueryRow(ctx, `
		UPDATE core.invitations SET token_hash = $2
		 WHERE id = $1::uuid AND email IS NOT NULL AND used_at IS NULL AND revoked_at IS NULL
		   AND expires_at > now()
		RETURNING email, org_id::text, expires_at`, canonical, hash).Scan(&email, &orgID, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", time.Time{}, ErrInvitationNotUsable
	}
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	return token, email, orgID, expires, nil
}

// CreateInvitation stores one, unsent, and returns its token.
func CreateInvitation(ctx context.Context, db *pgxpool.Pool, orgID, email string,
	groups []string, ttl time.Duration, createdBy string) (token string, err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, token, _, err = NewInvitation(ctx, tx, InvitationSpec{OrgID: orgID, Email: email,
		Groups: groups, TTL: ttl, CreatedBy: createdBy})
	if err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}

// ErrInvitationNotRevocable means no open invitation in that organisation has
// that id: it does not exist, belongs elsewhere, or was already used or
// revoked. One answer for all, as ClaimInvitation gives one answer.
var ErrInvitationNotRevocable = errors.New("no open invitation with that id in that organisation")

// RevokeInvitation closes an open invitation, audited, in one transaction.
//
// ClaimInvitation and PeekInvitation refused a revoked invitation from the
// start, and nothing could revoke one: a link sent to the wrong address, or
// to somebody who has since left, stayed good until it expired.
func RevokeInvitation(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}, orgID, id string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := RevokeInvitationIn(ctx, tx, orgID, id, audit.Event{Detail: map[string]any{"via": "cli"}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokeInvitationIn is RevokeInvitation in the caller's transaction, recorded
// as rec says who did it (the Admin API's token, 5.18).
func RevokeInvitationIn(ctx context.Context, tx pgx.Tx, orgID, id string, rec audit.Event) error {
	canonical, ok := CanonicalUUID(id)
	if !ok {
		return ErrInvitationNotRevocable
	}
	var email *string
	if err := tx.QueryRow(ctx, `
		UPDATE core.invitations SET revoked_at = now()
		 WHERE id = $1::uuid AND org_id = $2::uuid AND used_at IS NULL AND revoked_at IS NULL
		RETURNING email`, canonical, orgID).Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvitationNotRevocable
		}
		return err
	}
	detail := map[string]any{"invitation": canonical, "bound": email != nil}
	for k, v := range rec.Detail {
		detail[k] = v
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "admin.invitation_revoked", OrgID: orgID, AdminTokenID: rec.AdminTokenID, Detail: detail,
	}); err != nil {
		return fmt.Errorf("auditing the revocation: %w", err)
	}
	return nil
}

// ClaimInvitation consumes a token, or refuses.
//
// One statement. The WHERE clause carries every condition -- unused, unrevoked,
// unexpired -- and the same statement sets used_at, so two simultaneous claims
// cannot both succeed: the second finds no row matching `used_at IS NULL`.
//
// The claimed-by user does not exist yet at this point, so used_by is filled in
// afterwards by MarkInvitationUser. Claiming first means a crash between the
// two leaves the invitation SPENT rather than reusable, which is the right way
// round for a credential.
func ClaimInvitation(ctx context.Context, db *pgxpool.Pool, token string) (*Invitation, error) {
	sum := sha256.Sum256([]byte(token))
	var inv Invitation
	var email *string
	err := db.QueryRow(ctx, `
		UPDATE core.invitations
		   SET used_at = now()
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND revoked_at IS NULL
		   AND expires_at > now()
		RETURNING id::text, org_id::text, email, grant_groups`, sum[:]).
		Scan(&inv.ID, &inv.OrgID, &email, &inv.Groups)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvitationNotUsable
		}
		return nil, err
	}
	if email != nil {
		inv.Email = *email
	}
	return &inv, nil
}

// PeekInvitation reports whether a token would work, without consuming it.
//
// For rendering the form: the page needs to know the bound address so it can be
// shown, and refusing only on submission would mean filling in a password
// before being told the link is dead.
func PeekInvitation(ctx context.Context, db *pgxpool.Pool, token string) (*Invitation, error) {
	sum := sha256.Sum256([]byte(token))
	var inv Invitation
	var email *string
	err := db.QueryRow(ctx, `
		SELECT id::text, org_id::text, email, grant_groups
		  FROM core.invitations
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL
		   AND expires_at > now()`, sum[:]).
		Scan(&inv.ID, &inv.OrgID, &email, &inv.Groups)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvitationNotUsable
		}
		return nil, err
	}
	if email != nil {
		inv.Email = *email
	}
	return &inv, nil
}

// MarkInvitationUser records which account an invitation produced.
func MarkInvitationUser(ctx context.Context, db *pgxpool.Pool, invitationID, userID string) error {
	_, err := db.Exec(ctx,
		`UPDATE core.invitations SET used_by = $2::uuid WHERE id = $1::uuid`,
		invitationID, userID)
	return err
}

// ReleaseInvitation puts one back after a failed signup.
//
// Called when the account could not be created after the claim succeeded --
// a duplicate address, a refused password. Without it, a user who mistypes
// something has burnt their invitation and has to ask for another.
func ReleaseInvitation(ctx context.Context, db *pgxpool.Pool, invitationID string) error {
	_, err := db.Exec(ctx, `
		UPDATE core.invitations SET used_at = NULL
		 WHERE id = $1::uuid AND used_by IS NULL`, invitationID)
	return err
}

// SignupRule is an organisation's open-signup policy.
type SignupRule struct {
	OrgID          string
	AllowedDomains []string
	DefaultGroups  []string
	RequireVerify  bool
	// RequireApproval makes a self-sign-up pending until an administrator
	// activates it (0186).
	RequireApproval bool
}

// LoadSignupRule returns the rule, or nil when the organisation does not accept
// self-signup. Nil is the default and the safe answer.
func LoadSignupRule(ctx context.Context, db *pgxpool.Pool, orgID string) (*SignupRule, error) {
	var r SignupRule
	r.OrgID = orgID
	err := db.QueryRow(ctx, `
		SELECT allowed_domains, default_groups, require_verified_email, require_approval
		  FROM core.signup_rules WHERE org_id = $1::uuid`, orgID).
		Scan(&r.AllowedDomains, &r.DefaultGroups, &r.RequireVerify, &r.RequireApproval)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// Permits reports whether an address may self-sign-up under this rule.
func (r *SignupRule) Permits(email string) bool {
	if r == nil {
		return false
	}
	if len(r.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range r.AllowedDomains {
		if strings.EqualFold(strings.TrimPrefix(d, "@"), domain) {
			return true
		}
	}
	return false
}
