package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// Token Status List's Status Provider (specs/token-status-list.txt §8). A verifier asks
// here about one credential by fetching the whole list it belongs to, which is the point:
// the question does not say which one.

const credentialStatusPath = "/oid4vci/status/"

func (s *Server) credentialStatusURI(listID string) string {
	return s.credentialIssuerID() + credentialStatusPath + listID
}

// credentialStatusPlace takes a place for a credential about to be signed.
func (s *Server) credentialStatusPlace(ctx context.Context, orgID, userID string, cfg oid4vci.Configuration,
	now time.Time) (*oid4vci.StatusPlace, error) {

	var expiresAt *time.Time
	if cfg.Lifetime > 0 {
		at := now.Add(cfg.Lifetime)
		expiresAt = &at
	}
	var place *oid4vci.StatusPlace
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		listID, index, err := store.AllocateCredentialStatus(ctx, tx, orgID, userID, cfg.ID, expiresAt)
		if err != nil {
			return err
		}
		place = &oid4vci.StatusPlace{Index: index, URI: s.credentialStatusURI(listID)}
		return nil
	})
	return place, err
}

// handleCredentialStatus answers §8.1's GET with a token made from what the database says
// now. Anybody may ask: a list says nothing of who is behind any place in it.
func (s *Server) handleCredentialStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// §8.4: "If the Server does not support the additional query parameter, it SHOULD
	// return a status code of 501 (Not Implemented)".
	if r.URL.Query().Has("time") {
		writeError(w, http.StatusNotImplemented, "not_implemented", "no historical status is kept")
		return
	}
	listID := r.PathValue("listID")
	invalid, known, err := store.InvalidCredentialStatuses(ctx, s.db, s.instanceID, listID)
	if err != nil {
		s.log.ErrorContext(ctx, "reading a status list", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if !known {
		writeError(w, http.StatusNotFound, "not_found", "no such status list")
		return
	}
	token, err := oid4vci.StatusListToken(s.credentialStatusURI(listID), s.credentialIssuerID(), invalid, time.Now(),
		func(payload []byte, typ string) (string, error) {
			key, kerr := s.cfg.Keys.Active(keys.ES256)
			if kerr != nil {
				return "", kerr
			}
			return tokens.NewSigner(key).SignRaw(payload, typ)
		})
	if err != nil {
		s.log.ErrorContext(ctx, "signing a status list", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	w.Header().Set("Content-Type", oid4vci.StatusTokenMedia)
	// §8.1: the endpoint "SHOULD support the use of Cross-Origin Resource Sharing".
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(oid4vci.StatusTokenTTL.Seconds())))
	if _, err := w.Write([]byte(token)); err != nil {
		s.log.InfoContext(ctx, "writing a status list", "err", err, "correlation_id", correlationID(ctx))
	}
}
