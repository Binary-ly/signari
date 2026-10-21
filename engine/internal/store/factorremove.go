package store

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// FactorKind is a sign-in method an administrator may remove: the table that
// holds it.
type FactorKind struct {
	Table string
	// Keyed says the table holds one row per credential rather than one per
	// user, so a delete needs the credential's own id.
	Keyed bool
	// Whole says a keyed kind may also be removed all at once, without an id.
	// Recovery codes are one authenticator spread over several rows: the
	// listing never shows their ids (it would be a list of the codes' handles
	// for no purpose), and the support call is "remove this person's codes",
	// including a set switched off for too many wrong attempts.
	Whole bool
}

// FactorKinds maps the name the Admin API and the CLI use to the table.
//
// A fixed map, never a request's value interpolated into SQL. The table name is
// the one part of the query that cannot be a bind parameter, so it must not
// come from the request at all -- and this is the shape where that mistake is
// easy, because the name and the table look interchangeable.
var FactorKinds = map[string]FactorKind{
	"totp":      {Table: "totp_credentials"},
	"email_otp": {Table: "email_otp_credentials"},
	"sms_otp":   {Table: "sms_otp_credentials"},
	"duo":       {Table: "duo_enrollments"},
	"webauthn":  {Table: "webauthn_credentials", Keyed: true},
	"recovery":  {Table: "recovery_codes", Keyed: true, Whole: true},
}

var (
	ErrUnknownFactor    = errors.New("no factor of that kind exists")
	ErrFactorIDRequired = errors.New("a person may hold several of these, so the one to remove must be named")
	ErrFactorNotFound   = errors.New("no such factor")
)

// OwnRemovable are the methods a person removes from their own account page:
// the ones with one row each. A passkey is removed by its own route, which
// refuses the last; Duo is enrolled and removed by an administrator; recovery
// codes are replaced, not removed, on their page.
var OwnRemovable = []string{"totp", "email_otp", "sms_otp"}

// RemoveOwnFactor removes one of a person's own sign-in methods in tx.
//
// Unlike RemoveFactor it ends no session: the person is the one signed in,
// having just proved a recent sign-in, as passkey removal works. When nothing
// remains that is a second factor, their recovery codes go too
// (recoveryCleared): a recovery code stands in for a lost second factor, and
// with none left it is a credential that opens nothing but is still a guess
// somebody can make at the code step.
func RemoveOwnFactor(ctx context.Context, tx pgx.Tx, userID, kind string) (recoveryCleared bool, err error) {
	if !slices.Contains(OwnRemovable, kind) {
		return false, ErrUnknownFactor
	}
	tag, err := tx.Exec(ctx, `DELETE FROM core.`+FactorKinds[kind].Table+` WHERE user_id = $1::uuid`, userID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, ErrFactorNotFound
	}
	has, err := HasSecondFactor(ctx, tx, userID)
	if err != nil || has {
		return false, err
	}
	tag, err = tx.Exec(ctx, `DELETE FROM core.recovery_codes WHERE user_id = $1::uuid`, userID)
	if err != nil {
		return false, err
	}
	if err := ClearRecoveryCodeFailures(ctx, tx, userID); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RemovedFactor is what removing a factor did.
type RemovedFactor struct {
	Removed       int64
	SessionsEnded int
	NoticesQueued int
}

// RemoveFactor removes one of a person's sign-in methods in tx, ends every
// session they hold, and queues a notice to them (AccountNotice).
//
// The sessions are the point, not a side effect: a reset is asked for because
// the factor is lost or in somebody else's hands, and a session that factor
// opened is still somebody's way in. The notice is the holder hearing about it
// on a channel independent of the person who did it. The Admin API's removal
// and the CLI's are this one function, so neither can do half.
func RemoveFactor(ctx context.Context, tx pgx.Tx, userID, kind, factorID string) (RemovedFactor, error) {
	var out RemovedFactor
	spec, ok := FactorKinds[kind]
	if !ok {
		return out, ErrUnknownFactor
	}
	if spec.Keyed && factorID == "" && !spec.Whole {
		return out, ErrFactorIDRequired
	}
	// The user_id predicate is present on BOTH branches: without it a caller
	// could delete another person's credential by id, which is the whole
	// tenancy boundary undone by an omitted clause.
	var tag pgconn.CommandTag
	var err error
	if spec.Keyed && factorID != "" {
		tag, err = tx.Exec(ctx,
			`DELETE FROM core.`+spec.Table+` WHERE user_id = $1::uuid AND id = $2::uuid`, userID, factorID)
	} else {
		tag, err = tx.Exec(ctx, `DELETE FROM core.`+spec.Table+` WHERE user_id = $1::uuid`, userID)
	}
	if err != nil {
		return out, err
	}
	if out.Removed = tag.RowsAffected(); out.Removed == 0 {
		return out, ErrFactorNotFound
	}
	// The whole set gone, its count of wrong attempts goes with it, so a set
	// generated afterwards does not inherit a disabled state.
	if kind == "recovery" && factorID == "" {
		if err := ClearRecoveryCodeFailures(ctx, tx, userID); err != nil {
			return out, err
		}
	}
	term, err := TerminateSessions(ctx, tx, "", userID, ReasonMFAReset)
	if err != nil {
		return out, fmt.Errorf("ending sessions after a factor reset: %w", err)
	}
	if term != nil {
		out.SessionsEnded, out.NoticesQueued = term.Sessions, term.Notices
	}
	if err := EnqueueAccountNotice(ctx, tx, AccountNotice{UserID: userID, Notice: NoticeFactorRemoved,
		Factor: kind}); err != nil {
		return out, err
	}
	return out, nil
}
