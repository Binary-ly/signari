package store

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// MailSender is the address an organisation's mail comes from. Empty, the
// deployment's: SIGNARI_MAIL_FROM.
type MailSender struct {
	From string
	Name string
}

// ErrMailSender is a sender that cannot be one.
var ErrMailSender = errors.New("a sender is one plain address, with an optional name of at most 100 characters and no line breaks; a name needs an address")

// Long enough for any name a person reads in a From line, and short enough that
// a header stays a line.
const maxMailSenderName = 100

// checkMailSender refuses what cannot go in a From header. An address with a
// display name inside it is refused too: the name has its own field, and two
// places to say it is how a message comes to read as somebody else.
func checkMailSender(from, name string) error {
	if from == "" {
		if name != "" {
			return ErrMailSender
		}
		return nil
	}
	parsed, err := mail.ParseAddress(from)
	if err != nil || parsed.Address != from || parsed.Name != "" {
		return ErrMailSender
	}
	if len([]rune(name)) > maxMailSenderName || strings.ContainsFunc(name, unicode.IsControl) {
		return ErrMailSender
	}
	return nil
}

// SetOrgMailSender sets the address an organisation's mail comes from, or with
// an empty address takes it back to the deployment's.
func SetOrgMailSender(ctx context.Context, tx pgx.Tx, orgID string, s MailSender) error {
	if err := checkMailSender(s.From, s.Name); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.organizations SET mail_from = NULLIF($2, ''), mail_from_name = NULLIF($3, '')
		 WHERE id = $1::uuid`, orgID, s.From, s.Name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrOrganizationNotFound
	}
	return nil
}

// OrgMailSender reads an organisation's sender. An organisation with none, or
// one that has gone, answers the empty sender, which is the deployment's.
func OrgMailSender(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, orgID string) (MailSender, error) {
	var s MailSender
	err := q.QueryRow(ctx, `
		SELECT COALESCE(mail_from, ''), COALESCE(mail_from_name, '')
		  FROM core.organizations WHERE id = $1::uuid`, orgID).Scan(&s.From, &s.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return MailSender{}, nil
	}
	return s, err
}

// UserMailSender is OrgMailSender for the organisation a person belongs to.
func UserMailSender(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID string) (MailSender, error) {
	var s MailSender
	err := q.QueryRow(ctx, `
		SELECT COALESCE(o.mail_from, ''), COALESCE(o.mail_from_name, '')
		  FROM core.users u JOIN core.organizations o ON o.id = u.org_id
		 WHERE u.id = $1::uuid`, userID).Scan(&s.From, &s.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return MailSender{}, nil
	}
	return s, err
}
