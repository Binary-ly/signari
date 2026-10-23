package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// An upstream subject linked by an administrator to a person, as `signari idp
// link` and the Admin API make it (2.60, 6.07): what the jwt-bearer grant
// resolves an assertion's sub against, since a key-publishing issuer signs
// nobody in and so no sign-in can make its links.

// ErrIdPLinkTaken is a link refused because the subject already acts as
// somebody else, or the person is already known to the provider by another
// subject. A link is never moved by making it again: until 0.37 that answered
// that the subject now acted as the new person while it went on acting as the
// old one.
var ErrIdPLinkTaken = errors.New("the provider already links that subject or that person elsewhere")

type idpLinkTaken struct{ msg string }

func (e idpLinkTaken) Error() string        { return e.msg }
func (e idpLinkTaken) Is(target error) bool { return target == ErrIdPLinkTaken }

// ErrIdPLinkUnknown is a link removed that does not exist.
var ErrIdPLinkUnknown = errors.New("the provider has no such link")

// ErrIdPLinkPersonElsewhere is a person not in the provider's organisation.
var ErrIdPLinkPersonElsewhere = errors.New("that person is not in the provider's organisation")

// LinkSubject makes subject at the organisation's provider of that slug act as
// the person, and reports whether it already did. The person must be in the
// provider's organisation.
func LinkSubject(ctx context.Context, q outpostDB, orgID, slug, userID, subject string) (already bool, err error) {
	var providerID string
	if err := q.QueryRow(ctx, `SELECT id::text FROM core.identity_providers WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&providerID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrProviderUnknown
		}
		return false, err
	}
	var inOrg bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.users WHERE id = $1::uuid AND org_id = $2::uuid)`,
		userID, orgID).Scan(&inOrg); err != nil {
		return false, err
	}
	if !inOrg {
		return false, ErrIdPLinkPersonElsewhere
	}
	var current string
	switch err := q.QueryRow(ctx, `SELECT user_id::text FROM core.federated_identities
		WHERE provider_id = $1::uuid AND subject = $2`, providerID, subject).Scan(&current); {
	case err == nil && current == userID:
		return true, nil
	case err == nil:
		return false, idpLinkTaken{fmt.Sprintf("%s at %s already acts as another person; unlink it first, so "+
			"moving it is a decision made in two steps rather than by repeating one", subject, slug)}
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	var other string
	switch err := q.QueryRow(ctx, `SELECT subject FROM core.federated_identities
		WHERE provider_id = $1::uuid AND user_id = $2::uuid`, providerID, userID).Scan(&other); {
	case err == nil:
		return false, idpLinkTaken{fmt.Sprintf("that person is already %q at %s, and a person is one subject "+
			"at a provider; unlink that first", other, slug)}
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	if _, err := q.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject,
		email_verified) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, false)`,
		providerID, userID, orgID, subject); err != nil {
		if isUniqueViolation(err) {
			return false, idpLinkTaken{fmt.Sprintf("%s at %s was linked by somebody else meanwhile", subject, slug)}
		}
		return false, fmt.Errorf("linking the subject: %w", err)
	}
	return false, nil
}

// UnlinkSubject removes a link at the organisation's provider of that slug:
// subject's, the person's, or, given both, subject's only if it is the
// person's. It answers the subject removed. The next assertion naming it is
// refused; the grant issues no refresh token, so nothing outlives it.
func UnlinkSubject(ctx context.Context, q outpostDB, orgID, slug, userID, subject string) (string, error) {
	if userID == "" && subject == "" {
		return "", errors.New("unlinking needs the subject or the person, or it would be every link")
	}
	var removed string
	err := q.QueryRow(ctx, `
		DELETE FROM core.federated_identities f USING core.identity_providers p
		 WHERE p.id = f.provider_id AND p.org_id = $1::uuid AND p.slug = $2
		   AND ($3 = '' OR f.subject = $3) AND ($4 = '' OR f.user_id::text = $4)
		RETURNING f.subject`, orgID, slug, subject, userID).Scan(&removed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrIdPLinkUnknown
	}
	return removed, err
}

// IdentityLink is one provider a person is linked to.
type IdentityLink struct {
	Slug, Kind, Subject string
	LinkedAt            time.Time
	// LastSignInAt is the last sign-in through the provider, nil for a link
	// an administrator made that nobody has signed in through.
	LastSignInAt *time.Time
}

// IdentityLinks lists the providers a person is linked to, by slug.
func IdentityLinks(ctx context.Context, q Querier, userID string) ([]IdentityLink, error) {
	rows, err := q.Query(ctx, `
		SELECT p.slug, p.kind, f.subject, f.linked_at, f.last_login_at
		  FROM core.federated_identities f JOIN core.identity_providers p ON p.id = f.provider_id
		 WHERE f.user_id = $1::uuid ORDER BY p.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityLink{}
	for rows.Next() {
		var l IdentityLink
		if err := rows.Scan(&l.Slug, &l.Kind, &l.Subject, &l.LinkedAt, &l.LastSignInAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
