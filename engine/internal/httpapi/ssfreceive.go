package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)


// handleSSFReceive accepts a pushed Security Event Token.
func (s *Server) handleSSFReceive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// The issuer is read from the UNVERIFIED payload, and used only to choose
	// which key set to verify against. That is safe -- picking the wrong source
	// means the signature fails -- and it is the only way to know whose keys to
	// use before checking anything.
	issuer, ok := unverifiedIssuer(raw)
	if !ok {
		writeSSFError(w, http.StatusBadRequest, "invalid_request",
			"the token could not be parsed")
		return
	}
	src, found, err := store.SourceByIssuer(ctx, s.db, issuer)
	if err != nil {
		s.log.Error("looking up a shared-signals source", "err", err)
		writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if !found {
		// Deliberately the same shape as a verification failure. Distinguishing
		// "we do not know that issuer" from "the signature is wrong" tells an
		// unauthenticated caller which issuers we are configured for.
		s.log.Info("shared-signals event from an unknown issuer",
			"issuer", issuer, "correlation_id", correlationID(ctx))
		writeSSFError(w, http.StatusUnauthorized, "access_denied", "")
		return
	}

	event, err := ssf.Verify(ctx, s.ssfKeys, src, raw, time.Now())
	if err != nil {
		s.log.Warn("shared-signals event refused", "issuer", issuer, "err", err,
			"correlation_id", correlationID(ctx))
		writeSSFError(w, http.StatusUnauthorized, "invalid_key", "")
		return
	}

	// Verified. Only now does anything get looked up or changed.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	userID, err := store.ResolveSSFSubject(ctx, tx, src.OrgID, event.Subject)
	if err != nil {
		s.log.Error("resolving a shared-signals subject", "err", err)
		writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	action, detail := "ignored", ""
	switch {
	case userID == "":
		// Normal. A transmitter sends events about people we have never seen,
		// and that is not an error -- but it IS recorded, because "we received
		// forty events about nobody" is how a misconfigured subject format
		// announces itself.
		action, detail = "no_matching_user", event.Subject.Sub

	case event.Type == ssf.EventSessionRevoked:
		n, terr := store.TerminateSessions(ctx, tx, "", userID, store.ReasonSharedSignal)
		if terr != nil {
			s.log.Error("terminating sessions from a shared signal", "err", terr)
			writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
			return
		}
		action = "sessions_revoked"
		detail = itoaInt(n.Sessions) + " session(s)"

	case event.Type == ssf.EventCredentialChange:
		// Somebody else's credential change is a reason to end our sessions
		// too: the same person's authentication elsewhere has changed, and a
		// session predating that change was established under the old one.
		n, terr := store.TerminateSessions(ctx, tx, "", userID, store.ReasonSharedSignal)
		if terr != nil {
			s.log.Error("terminating sessions from a credential change", "err", terr)
			writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
			return
		}
		action = "sessions_revoked"
		detail = "credential change upstream; " + itoaInt(n.Sessions) + " session(s)"

	case event.Type == ssf.EventAssuranceChange:
		// A drop in assurance is not the same as a revocation, and treating it
		// as one would sign people out for stepping DOWN from a hardware key to
		// a password on a second device. Recorded; the policy layer decides.
		action = "recorded"
		detail = "assurance level changed upstream"

	default:
		action, detail = "ignored", "no handler for "+event.Type
	}

	// Recorded BEFORE the commit, in the same transaction, so the replay guard
	// and the effect land together. A revocation that committed without its
	// record could be replayed.
	if err := store.RecordReceived(ctx, tx, src.ID, src.OrgID, event,
		userID, action, detail); err != nil {
		if errors.Is(err, store.ErrReplayed) {
			// A replay is not an error to the sender: at-least-once delivery
			// means a transmitter legitimately resends, and answering 4xx would
			// make it retry forever. Accepted, and nothing repeated.
			s.log.Info("shared-signals event replayed", "issuer", issuer,
				"jti", event.JTI, "correlation_id", correlationID(ctx))
			w.WriteHeader(http.StatusAccepted)
			return
		}
		s.log.Error("recording a shared-signals event", "err", err)
		writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	if err := audit.Write(ctx, tx, audit.Event{
		Type: "ssf.received", OrgID: src.OrgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"issuer": issuer, "event": event.Type, "action": action, "detail": detail,
		},
	}); err != nil {
		s.log.Error("auditing a shared-signals event", "err", err)
	}

	if err := tx.Commit(ctx); err != nil {
		s.log.Error("committing a shared-signals event", "err", err)
		writeSSFError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	s.log.Info("shared-signals event applied", "issuer", issuer,
		"event", event.Type, "action", action, "detail", detail)
	// 202: accepted and acted on. RFC 8935 expects 202 with an empty body.
	w.WriteHeader(http.StatusAccepted)
}

// unverifiedIssuer reads `iss` from a compact JWS without verifying it.
//
// Used ONLY to choose which key set to verify against. Choosing wrongly makes
// the signature fail, so this cannot grant anything -- but it must never be
// used for a decision, and it is not.
func unverifiedIssuer(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Issuer == "" {
		return "", false
	}
	return c.Issuer, true
}

// writeSSFError answers in the shape RFC 8935 §2.3 defines.
func writeSSFError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]string{"err": code}
	if description != "" {
		body["description"] = description
	}
	_ = json.NewEncoder(w).Encode(body)
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
