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

// CreateInvitation stores one.
func CreateInvitation(ctx context.Context, db *pgxpool.Pool, orgID, email string,
	groups []string, ttl time.Duration, createdBy string) (token string, err error) {

	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	token, hash, err := NewInvitationToken()
	if err != nil {
		return "", err
	}
	if groups == nil {
		groups = []string{}
	}
	var by any
	if createdBy != "" {
		by = createdBy
	}
	_, err = db.Exec(ctx, `
		INSERT INTO core.invitations
			(org_id, token_hash, email, grant_groups, expires_at, created_by)
		VALUES ($1::uuid, $2, NULLIF($3,''), $4, now() + $5::interval, $6::uuid)`,
		orgID, hash, strings.ToLower(strings.TrimSpace(email)), groups,
		fmt.Sprintf("%d seconds", int(ttl.Seconds())), by)
	if err != nil {
		return "", err
	}
	return token, nil
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
}

// LoadSignupRule returns the rule, or nil when the organisation does not accept
// self-signup. Nil is the default and the safe answer.
func LoadSignupRule(ctx context.Context, db *pgxpool.Pool, orgID string) (*SignupRule, error) {
	var r SignupRule
	r.OrgID = orgID
	err := db.QueryRow(ctx, `
		SELECT allowed_domains, default_groups, require_verified_email
		  FROM core.signup_rules WHERE org_id = $1::uuid`, orgID).
		Scan(&r.AllowedDomains, &r.DefaultGroups, &r.RequireVerify)
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
