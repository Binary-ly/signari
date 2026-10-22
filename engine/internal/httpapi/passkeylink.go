package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/mail"
	"signari.dev/engine/internal/store"
)

// Registering a passkey from an emailed link, with no session (migration
// 0176): a new starter who has no password, or somebody whose only way in is
// lost. An administrator issues the link (`signari user passkey-link`, POST
// /admin/users/{userID}/passkey-link); the outbox worker mints its token as it
// emails it to the account's own address (DeliverAccountNotice).
//
// The link is a credential while it lives, so it is spent by exactly one
// thing: the transaction that stores the passkey. Opening the page spends
// nothing -- a mail scanner fetches every link it is shown -- and beginning a
// ceremony spends nothing, so a ceremony abandoned halfway leaves the link
// usable. The ceremony carries the link's id, so finishing needs no token, and
// a link superseded or used between the two halves is refused there.

// ceremonyLinkRegister is the ceremony an emailed link begins. Its own
// purpose, so it can be finished only here and the account page's only there.
const ceremonyLinkRegister = "link-register"

// handlePasskeyLinkPage shows the page a link opens.
func (s *Server) handlePasskeyLinkPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	link, err := s.findPasskeyLink(ctx, token)
	var account string
	if err == nil {
		err = s.db.QueryRow(ctx, `SELECT COALESCE(email, username, '') FROM core.users
			WHERE id = $1::uuid`, link.UserID).Scan(&account)
	}
	if err != nil {
		if !errors.Is(err, store.ErrPasskeyLinkInvalid) {
			s.log.Error("reading a passkey link", "err", err)
		}
		s.renderPageStatus(w, r, http.StatusNotFound, "passkeylink", map[string]any{
			"Error": s.tr(r).T("error.passkeylink.invalid"),
		})
		return
	}
	s.renderPage(w, r, "passkeylink", map[string]any{
		"Ready": true, "Token": token, "Account": account,
		"Until":         link.ExpiresAt.UTC().Format("15:04 MST on 2 January"),
		"PasskeyScript": true,
	})
}

// handlePasskeyLinkBegin starts the ceremony for the link in the body,
// {"token": "..."}.
func (s *Server) handlePasskeyLinkBegin(w http.ResponseWriter, r *http.Request) {
	// The same CORS-preflight defence as the account page's (jsonct.go).
	if err := requireJSONContentType(r); err != nil {
		writeJSONContentTypeError(w, err)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "a JSON body with the link's token")
		return
	}
	link, err := s.findPasskeyLink(r.Context(), body.Token)
	if err != nil {
		if !errors.Is(err, store.ErrPasskeyLinkInvalid) {
			s.log.Error("reading a passkey link", "err", err)
		}
		writeError(w, http.StatusBadRequest, "invalid_request", store.ErrPasskeyLinkInvalid.Error())
		return
	}
	s.beginPasskeyRegistration(w, r, ceremonyClaims{
		Purpose: ceremonyLinkRegister, Subject: link.UserID, OrgID: link.OrgID, Link: link.ID,
	})
}

// handlePasskeyLinkFinish stores the passkey and spends the link, together.
func (s *Server) handlePasskeyLinkFinish(w http.ResponseWriter, r *http.Request) {
	if err := requireJSONContentType(r); err != nil {
		writeJSONContentTypeError(w, err)
		return
	}
	defer s.clearCeremony(w)
	cl, sd, err := s.readCeremony(r, ceremonyLinkRegister)
	if err == nil && (cl.Link == "" || cl.Subject == "") {
		err = errors.New("a link ceremony naming no link")
	}
	if err != nil {
		s.log.Info("link registration ceremony rejected", "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request", "no valid registration in progress")
		return
	}
	ctx := r.Context()
	s.finishPasskeyRegistration(w, r, cl.Subject, cl.OrgID, sd, func(tx pgx.Tx) error {
		if err := store.SpendPasskeyLink(ctx, tx, cl.Link, cl.Subject); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Event{
			Type: "mfa.passkey_link_used", OrgID: cl.OrgID, SubjectID: cl.Subject,
			CorrelationID: correlationID(ctx),
			Detail:        map[string]any{"link_id": cl.Link},
		})
	})
}

// deliverPasskeyLink emails a link to the account's own address, minting the
// token it carries. Email alone: the link is the credential, and the address
// it goes to is the one the administrator who issued it vouched for. The
// passkey it registers is announced on every channel, as any is.
func (s *Server) deliverPasskeyLink(ctx context.Context, n store.AccountNotice) error {
	var email string
	err := s.db.QueryRow(ctx, `SELECT COALESCE(email, '') FROM core.users
		WHERE id = $1::uuid AND status = 'active'`, n.UserID).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && email == "") {
		// Deactivated, or the address removed, since it was issued. Nothing to
		// send, and trying again will not change that.
		s.log.Warn("a passkey link was not sent: the account has no address to send it to",
			"user_id", n.UserID, "link_id", n.LinkID)
		return nil
	}
	if err != nil {
		return err
	}
	token, expires, err := store.MintPasskeyLinkToken(ctx, s.db, n.LinkID)
	if errors.Is(err, store.ErrPasskeyLinkInvalid) {
		// Used, expired or superseded before it went out.
		return nil
	}
	if err != nil {
		return err
	}
	tr := s.notifierFor(ctx, n.UserID)
	return s.mailer.Send(ctx, mail.Message{
		To:      email,
		Subject: tr.Text("mail.passkeylink.subject"),
		Body: tr.Text("mail.passkeylink.body", map[string]any{
			"URL":   s.cfg.Issuer + "/enrol/passkey?token=" + url.QueryEscape(token),
			"Until": expires.UTC().Format("15:04 MST on 2 January"),
		}),
	})
}
