package adminapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// Second-factor administration.
//
// # Why this has to exist
//
// The support call this answers is the commonest one an identity provider
// receives: somebody's phone is lost, stolen, or wiped, and the authenticator on
// it was the only way into their account. Without an endpoint, the options are
// SQL against schema `core` -- which the console has no privilege for at all
// (ADR-004), so it means a shell on a database host -- or the person stays
// locked out. Both are worse than the operation itself.
//
// # Removing a factor ends the person's sessions
//
// store.ReasonMFAReset existed as a constant with no caller until this file.
// That is the reason it existed.
//
// The scenario that decides it is the stolen phone, and the decision is not
// about the victim: it is about whoever is holding the device. If the thief
// already signed in, removing the enrolment they are no longer using does
// nothing to the session they ARE using. Termination is the half of "reset this
// person's second factor" that a support desk actually means, and it is
// invisible if you think of the operation as editing a row.
//
// It is also the honest thing to do about assurance. Those sessions were minted
// with an `acr` asserting multi-factor authentication. The factor backing that
// assertion is now gone, so continuing to serve them means continuing to assert
// something that stopped being true.
//
// # Removing the last factor is allowed
//
// Deliberately, and it is the main use case rather than an edge: a person who
// cannot produce their only factor is exactly who this rescues. Refusing would
// leave the endpoint unable to do the thing it was built for.
//
// It is safe because the sign-in path already handles the resulting state. An
// organisation whose flow demands MFA meets an account with nothing enrolled and
// refuses the sign-in with an enrolment message (httpapi/flowdrive.go), rather
// than waving it through as single-factor. The gate is on the flow, not on the
// presence of a row here, so deleting the row cannot downgrade anybody.
//
// # No secret material, on any response
//
// The listing returns what a factor IS, never what it holds: no TOTP secret
// (even encrypted), no code hash, no public key, no phone number, no address. A
// read scope must not be a slower route to the power a write scope has, and the
// way that rule normally breaks is somebody selecting `*` because it was
// convenient. There is a test asserting the absence.

// factorKinds maps the URL segment to the table holding it.
//
// A fixed map, never the path value interpolated into SQL. The table name is the
// one part of this query that cannot be a bind parameter, so it must not come
// from the request at all -- and this is the shape where that mistake is easy,
// because the segment and the table name look interchangeable.
var factorKinds = map[string]struct {
	table string
	// keyed says the table holds one row per credential rather than one per
	// user, so a delete needs the credential's own id.
	keyed bool
}{
	"totp":      {table: "totp_credentials"},
	"email_otp": {table: "email_otp_credentials"},
	"sms_otp":   {table: "sms_otp_credentials"},
	"duo":       {table: "duo_enrollments"},
	"webauthn":  {table: "webauthn_credentials", keyed: true},
	"recovery":  {table: "recovery_codes", keyed: true},
}

type factorSummary struct {
	Type string `json:"type"`
	// ID is present only for factor kinds a user may hold several of. For the
	// rest the user is the key, and inventing an id would imply a second one
	// could be added.
	ID    string `json:"id,omitempty"`
	Label string `json:"label,omitempty"`
	// Confirmed distinguishes an enrolment that was completed from one that was
	// started and abandoned. An unconfirmed TOTP row is not a usable factor and
	// reporting it as one would have a support desk delete the wrong thing.
	Confirmed bool   `json:"confirmed"`
	CreatedAt string `json:"created_at,omitempty"`
	LastUsed  string `json:"last_used_at,omitempty"`
}

// listUserFactors reports what a person can authenticate with.
func (s *Server) listUserFactors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")

	var orgID string
	if err := s.db.QueryRow(ctx,
		`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		s.log.Error("reading the user for a factor listing", "user_id", userID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := requireOrg(ctx, orgID); err != nil {
		writeCrossOrg(w, err)
		return
	}

	out := []factorSummary{}

	// TOTP. `confirmed_at` rather than the row's existence: enrolment writes the
	// row before the first code is checked, so an abandoned attempt leaves one
	// behind that never worked.
	var totpConfirmed *string
	var totpCreated string
	err := s.db.QueryRow(ctx, `
		SELECT confirmed_at::text, created_at::text
		FROM core.totp_credentials WHERE user_id = $1::uuid`, userID).
		Scan(&totpConfirmed, &totpCreated)
	switch {
	case err == nil:
		out = append(out, factorSummary{
			Type: "totp", Confirmed: totpConfirmed != nil, CreatedAt: totpCreated,
		})
	case !errors.Is(err, pgx.ErrNoRows):
		s.log.Error("listing totp", "err", err)
	}

	// WebAuthn. friendly_name is the label the person chose; the public key,
	// credential id and AAGUID stay here.
	rows, err := s.db.Query(ctx, `
		SELECT id::text, COALESCE(friendly_name,''), created_at::text,
		       COALESCE(last_used_at::text,'')
		FROM core.webauthn_credentials WHERE user_id = $1::uuid ORDER BY created_at`, userID)
	if err != nil {
		s.log.Error("listing webauthn credentials", "err", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var f factorSummary
			if err := rows.Scan(&f.ID, &f.Label, &f.CreatedAt, &f.LastUsed); err != nil {
				continue
			}
			f.Type, f.Confirmed = "webauthn", true
			out = append(out, f)
		}
	}

	// Email and SMS one-time codes. The address and the number are NOT returned:
	// they are the personal data this endpoint has no reason to disclose, and an
	// operator deciding whether to remove a factor does not need to read it.
	for _, k := range []struct{ kind, table string }{
		{"email_otp", "email_otp_credentials"},
		{"sms_otp", "sms_otp_credentials"},
	} {
		var created string
		// The table name is from this fixed list, never from the request.
		if err := s.db.QueryRow(ctx,
			`SELECT created_at::text FROM core.`+k.table+` WHERE user_id = $1::uuid`,
			userID).Scan(&created); err == nil {
			out = append(out, factorSummary{Type: k.kind, Confirmed: true, CreatedAt: created})
		} else if !errors.Is(err, pgx.ErrNoRows) {
			s.log.Error("listing otp credentials", "kind", k.kind, "err", err)
		}
	}

	var duoCreated string
	if err := s.db.QueryRow(ctx,
		`SELECT created_at::text FROM core.duo_enrollments WHERE user_id = $1::uuid`,
		userID).Scan(&duoCreated); err == nil {
		out = append(out, factorSummary{Type: "duo", Confirmed: true, CreatedAt: duoCreated})
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("listing duo enrolments", "err", err)
	}

	// Recovery codes are reported as a COUNT of unused ones, never listed. A
	// list would be the codes themselves.
	var unused int
	if err := s.db.QueryRow(ctx, `
		SELECT count(*) FROM core.recovery_codes
		WHERE user_id = $1::uuid AND used_at IS NULL`, userID).Scan(&unused); err != nil {
		s.log.Error("counting recovery codes", "err", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":               userID,
		"factors":               out,
		"recovery_codes_unused": unused,
		"has_second_factor":     len(out) > 0,
	})
}

// deleteUserFactor removes one enrolment and ends the person's sessions.
func (s *Server) deleteUserFactor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("userID")
	kind := r.PathValue("kind")

	spec, ok := factorKinds[kind]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown_factor", "detail": "no factor of that kind exists",
		})
		return
	}
	factorID := r.PathValue("factorID")
	if spec.keyed && factorID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "factor_id_required",
			"detail": "a user may hold several of these, so the one to remove " +
				"must be named",
		})
		return
	}

	pre, preOK := s.readPrecondition(w, r)
	if !preOK {
		return
	}

	var removed int64
	var ended, notified int
	version, err := s.mutateIf(ctx, pre, func(tx pgx.Tx) error {
		var orgID string
		if err := tx.QueryRow(ctx,
			`SELECT org_id::text FROM core.users WHERE id = $1::uuid`, userID).Scan(&orgID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errNotFound
			}
			return err
		}
		if err := requireOrg(ctx, orgID); err != nil {
			return err
		}

		// The table comes from factorKinds, the values are bound. The user_id
		// predicate is present on BOTH branches: without it a caller could
		// delete another user's credential by id, which is the whole tenancy
		// boundary undone by an omitted clause.
		var tag pgconn.CommandTag
		var execErr error
		if spec.keyed {
			tag, execErr = tx.Exec(ctx,
				`DELETE FROM core.`+spec.table+` WHERE user_id = $1::uuid AND id = $2::uuid`,
				userID, factorID)
		} else {
			tag, execErr = tx.Exec(ctx,
				`DELETE FROM core.`+spec.table+` WHERE user_id = $1::uuid`, userID)
		}
		if execErr != nil {
			return execErr
		}
		removed = tag.RowsAffected()
		if removed == 0 {
			return errNotFound
		}

		// See the file comment: the sessions are the point, not a side effect.
		term, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonMFAReset)
		if err != nil {
			return fmt.Errorf("ending sessions after a factor reset: %w", err)
		}
		if term != nil {
			ended, notified = term.Sessions, term.Notices
		}

		return audit.Write(ctx, tx, audit.Event{
			Type: "admin.factor_removed", AdminTokenID: TokenIDFrom(ctx),
			OrgID: orgID, SubjectID: userID,
			Detail: map[string]any{
				"factor":         kind,
				"removed":        removed,
				"sessions_ended": ended,
				"notices_queued": notified,
			},
		})
	})

	switch {
	case err != nil && writePreconditionFailure(w, err):
		return
	case errors.Is(err, errCrossOrg):
		writeCrossOrg(w, err)
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "factor_not_found"})
		return
	case err != nil:
		s.log.Error("removing a factor", "user_id", userID, "factor", kind, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setETag(w, version)
	s.log.Warn("second factor removed", "user_id", userID, "factor", kind,
		"removed", removed, "sessions_ended", ended, "config_version", version)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": userID, "factor": kind, "removed": removed,
		"sessions_ended": ended, "notices_queued": notified,
		"config_version": version,
	})
}
