package httpapi

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/passwords"
	"signari.dev/engine/internal/store"
)

// Creating an account: by invitation, or by an organisation's signup rule.
//
// # Two routes, one endpoint
//
// `/signup?invite=…` accepts an invitation. `/signup` on its own is open
// self-signup, which works only if the organisation has a rule permitting it.
// The two share a form because they produce the same thing, and differ in what
// is checked before they will.
//
// # Why self-signup is a rule and not a switch
//
// "Anyone may sign up" is almost never what an organisation means. "Anyone with
// an @acme.com address" usually is, and a checkbox cannot express the
// difference. So an organisation either has a rule -- which names the domains
// and the groups a new account joins -- or it does not accept self-signup at
// all. There is no setting whose value is "yes, to everyone", reachable by
// accident.
//
// # The invitation is claimed before the account is made
//
// Claiming first means a crash between the two leaves the invitation spent
// rather than reusable, which is the correct direction for a credential. A
// signup that then fails for an ordinary reason -- the address is taken, the
// password is too short -- releases it again, so a typo does not cost somebody
// their invitation.

// signupMinPassword matches the recovery reset path. Two different minimums for
// the same field is the kind of inconsistency users discover by being refused.
const signupMinPassword = 8

// How many accounts one address may create in an hour.
//
// This endpoint writes rows and, in a deployment with mail configured, sends
// messages. Ten is far above any legitimate use -- a person creates one account
// -- and far below what makes a useful flooding tool.
const (
	signupsPerWindow = 10
	signupWindow     = time.Hour
)

// handleSignupGet renders the form.
func (s *Server) handleSignupGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	csrf, err := s.csrfToken(w, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	data := s.captchaFields(r, map[string]any{"CSRF": csrf, "CSRFField": csrfFormField})

	if token := r.URL.Query().Get("invite"); token != "" {
		inv, err := store.PeekInvitation(ctx, s.db, token)
		if err != nil {
			// Said now rather than after a password has been chosen. Refusing on
			// submission means filling in a form to be told the link was dead
			// before it was opened.
			s.renderPage(w, r, "signup", s.captchaFields(r, map[string]any{
				"Error": "That invitation link is not valid. It may have been used " +
					"already, or expired. Ask whoever invited you for a new one.",
			}))
			return
		}
		data["Invite"] = token
		data["Email"] = inv.Email
		// A bound invitation fixes the address; showing it editable invites
		// someone to change it and then be refused for no visible reason.
		data["EmailFixed"] = inv.Email != ""
		s.renderPage(w, r, "signup", data)
		return
	}

	rule, err := s.signupRule(ctx)
	if err != nil || rule == nil {
		// The same answer whether the organisation has no rule or none was
		// found: an endpoint that distinguishes them reports whether an
		// organisation exists to anyone who asks.
		http.NotFound(w, r)
		return
	}
	if len(rule.AllowedDomains) > 0 {
		data["Domains"] = strings.Join(rule.AllowedDomains, ", ")
	}
	s.renderPage(w, r, "signup", data)
}

// handleSignupPost creates the account.
func (s *Server) handleSignupPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !checkCSRF(r) {
		writeError(w, http.StatusForbidden, "forbidden", "that form has expired; reload and try again")
		return
	}

	// Rate limited on the address, because this endpoint creates rows and sends
	// mail. Without it, one script fills the users table and the mail queue.
	if res, err := store.AllowRate(ctx, s.db, "signup:ip:"+clientIP(r),
		signupsPerWindow, signupWindow); err == nil && !res.Allowed {
		writeError(w, http.StatusTooManyRequests, "slow_down",
			"too many attempts from this address; wait a few minutes")
		return
	}

	// The challenge, checked before anything is created.
	//
	// `internal/flow`'s shipped enrolment flow has declared
	// `{stage: captcha, when: captcha_required}` since it was written, and this
	// endpoint had no challenge at all -- the only `captcha.Verify` in the engine
	// was on the sign-in path. So an operator who configured a provider got it on
	// the endpoint that checks a password and not on the endpoint that writes
	// rows and sends mail, while the flow file told them otherwise.
	//
	// A failure is recorded, like the sign-in path, so adaptive mode escalates
	// rather than being held still by a stream of blank submissions.
	if s.captcha.Required(ctx, r.RemoteAddr) {
		if cerr := s.captcha.Verify(ctx, captchaResponse(r), r.RemoteAddr); cerr != nil {
			s.captcha.RecordFailure(ctx, r.RemoteAddr)
			s.log.Info("captcha refused at sign-up", "err", cerr,
				"correlation_id", correlationID(ctx))
			csrf, _ := s.csrfToken(w, r)
			s.renderPage(w, r, "signup", s.captchaFields(r, map[string]any{
				"Error":  "That challenge was not completed. Please try again.",
				"Email":  strings.ToLower(strings.TrimSpace(r.PostFormValue("email"))),
				"Invite": r.PostFormValue("invite"),
				"CSRF":   csrf, "CSRFField": csrfFormField,
			}))
			return
		}
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	token := r.PostFormValue("invite")

	fail := func(msg string) {
		csrf, _ := s.csrfToken(w, r)
		// The widget is re-rendered on failure. Without it the form comes back
		// with no challenge, the next submission has nothing to send, and the
		// person is refused for a reason the page does not show them.
		s.renderPage(w, r, "signup", s.captchaFields(r, map[string]any{
			"Error": msg, "Email": email, "Invite": token,
			"CSRF": csrf, "CSRFField": csrfFormField,
		}))
	}

	if email == "" || !strings.Contains(email, "@") {
		fail("Enter the email address this account should use.")
		return
	}
	// The shared gate: length, context, reuse and the breach corpus. Not a
	// local length check, because a second place to decide what a password may
	// be is a second place for it to be weaker.
	if res, perr := s.pwPolicy.Check(ctx, password, email, nil, s.hasher); perr != nil {
		fail(perr.Error())
		return
	} else if s.pwPolicy.Breach != nil && !res.BreachCheckRan {
		// The check was configured and could not run. Logged loudly: a control
		// that quietly stopped running is worse than one never configured.
		s.log.Warn("the breach check did not run for a new password",
			"correlation_id", correlationID(ctx))
	}

	var orgID string
	var groups []string
	var invitationID string

	if token != "" {
		inv, err := store.ClaimInvitation(ctx, s.db, token)
		if err != nil {
			// A link that is genuinely spent and a database that refused the
			// write are the same message to the user and must not be the same
			// to us: the first is normal, the second is a bug, and treating
			// them alike is how a broken claim looks like a stale link.
			if !errors.Is(err, store.ErrInvitationNotUsable) {
				s.log.Error("claiming an invitation failed unexpectedly", "err", err)
			}
			fail("That invitation link is not valid. It may have been used " +
				"already, or expired.")
			return
		}
		invitationID, orgID, groups = inv.ID, inv.OrgID, inv.Groups
		// A bound invitation may only produce the account it named. Without
		// this, a leaked link is an account in the organisation under any
		// address the finder chooses.
		if inv.Email != "" && !strings.EqualFold(inv.Email, email) {
			_ = store.ReleaseInvitation(ctx, s.db, inv.ID)
			fail("This invitation is for " + inv.Email + ". Sign up with that address.")
			return
		}
	} else {
		rule, err := s.signupRule(ctx)
		if err != nil || rule == nil {
			http.NotFound(w, r)
			return
		}
		if !rule.Permits(email) {
			fail("That address cannot create an account here. Allowed: " +
				strings.Join(rule.AllowedDomains, ", "))
			return
		}
		orgID, groups = rule.OrgID, rule.DefaultGroups
	}

	userID, err := s.createAccount(ctx, orgID, email, password, groups)
	if err != nil {
		if invitationID != "" {
			// Give it back. A duplicate address or a refused password should not
			// cost somebody the invitation they were sent.
			_ = store.ReleaseInvitation(ctx, s.db, invitationID)
		}
		if errors.Is(err, errAddressTaken) {
			fail("There is already an account with that address. Try signing in, " +
				"or use the forgotten-password link.")
			return
		}
		s.log.Error("creating an account", "err", err)
		fail("The account could not be created. Reference: " +
			shortCode(correlationID(ctx)))
		return
	}
	if invitationID != "" {
		if err := store.MarkInvitationUser(ctx, s.db, invitationID, userID); err != nil {
			s.log.Error("recording who used an invitation", "err", err)
		}
	}

	s.auditDetached(ctx, audit.Event{
		Type: "user.created", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"route":  map[bool]string{true: "invitation", false: "self-signup"}[invitationID != ""],
			"groups": groups,
		},
	})

	s.renderPage(w, r, "signupdone", map[string]any{"Email": email})
}

// createAccount makes the user, the password credential and the memberships.
//
// One transaction. A user with no credential cannot sign in and cannot recover
// -- there is nothing to send a reset to that proves anything -- so a partial
// success here is an account that has to be deleted by hand.
func (s *Server) createAccount(ctx context.Context, orgID, email, password string,
	groups []string) (string, error) {

	handle := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, handle); err != nil {
		return "", err
	}
	hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return "", err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, $2, $3) RETURNING id::text`, orgID, handle, email).Scan(&userID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return "", errAddressTaken
		}
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, userID, orgID, hash); err != nil {
		return "", err
	}
	for _, g := range groups {
		// The group must already exist. Creating one here would let an
		// invitation invent a group name, and group names are what policies are
		// written against.
		var groupID string
		err := tx.QueryRow(ctx,
			`SELECT id::text FROM core.groups WHERE org_id = $1::uuid AND name = $2`,
			orgID, g).Scan(&groupID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				s.log.Warn("an invitation named a group that does not exist",
					"group", g, "org", orgID)
				continue
			}
			return "", err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO core.group_members (group_id, user_id, org_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid)
			ON CONFLICT DO NOTHING`, groupID, userID, orgID); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}

var errAddressTaken = errors.New("an account with that address already exists")

// signupRule reads the rule for the organisation this instance serves.
func (s *Server) signupRule(ctx context.Context) (*store.SignupRule, error) {
	orgID, err := s.defaultOrg(ctx)
	if err != nil || orgID == "" {
		return nil, err
	}
	return store.LoadSignupRule(ctx, s.db, orgID)
}
