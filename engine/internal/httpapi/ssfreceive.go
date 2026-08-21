package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
		writeSSFError(w, http.StatusBadRequest, errInvalidRequest,
			"the request body could not be parsed as a SET")
		return
	}
	src, found, err := store.SourceByIssuer(ctx, s.db, issuer)
	if err != nil {
		s.log.Error("looking up a shared-signals source", "err", err)
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
		return
	}
	if !found {
		// Deliberately the same shape as a verification failure. Distinguishing
		// "we do not know that issuer" from "the signature is wrong" tells an
		// unauthenticated caller which issuers we are configured for.
		s.log.Info("shared-signals event from an unknown issuer",
			"issuer", issuer, "correlation_id", correlationID(ctx))
		// §2.4: invalid_issuer is "The SET Issuer is invalid for the SET
		// Recipient", which is exactly this. 400 per §2.3.
		writeSSFError(w, http.StatusBadRequest, errInvalidIssuer,
			"no source is configured for that issuer")
		return
	}

	event, err := ssf.Verify(ctx, s.ssfKeys, src, raw, time.Now())
	if err != nil {
		s.log.Warn("shared-signals event refused", "issuer", issuer, "err", err,
			"correlation_id", correlationID(ctx))
		// The registry distinguishes these, and a transmitter that cannot tell
		// a wrong audience from a wrong key cannot fix its configuration.
		code, desc := ssfErrorCode(err)
		writeSSFError(w, http.StatusBadRequest, code, desc)
		return
	}

	// Verified. Only now does anything get looked up or changed.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	userID, err := store.ResolveSSFSubject(ctx, tx, src.OrgID, event.Subject)
	if err != nil {
		s.log.Error("resolving a shared-signals subject", "err", err)
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
		return
	}

	// EVERY entry is applied, in this one transaction.
	//
	// Accepting a multi-entry token and acting on only the first would be worse
	// than refusing it: the transmitter is told 202 and believes all of it
	// landed. One transaction is what makes "all of it or none of it" true.
	action, detail := s.applySignals(ctx, tx, event, userID)
	if action == "" {
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
		return
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
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
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
		writeSSFError(w, http.StatusInternalServerError, errInvalidRequest, "")
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

// SET error codes from the IANA registry, RFC 8935 §2.4.
//
// Only registered names. The first version used "internal_error", which is not
// in the registry -- a transmitter matching on the code would have no idea what
// it meant, and the registry exists precisely so it does not have to guess.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidKey           = "invalid_key"
	errInvalidIssuer        = "invalid_issuer"
	errInvalidAudience      = "invalid_audience"
	errAuthenticationFailed = "authentication_failed"
	errAccessDenied         = "access_denied"
)

// writeSSFError answers in the shape RFC 8935 §2.3 requires.
//
// # 400, not 401
//
// "When the SET Recipient detects an error parsing, validating, or
// authenticating a SET ... the SET Recipient SHALL respond with an HTTP
// Response Status Code of 400 (Bad Request)."
//
// The first version answered 401 for verification failures and for unknown
// issuers, reasoning that a uniform response avoids telling an unauthenticated
// caller which issuers we are configured for. That reasoning traded a small
// disclosure for a conformance break and, worse, for an integration that cannot
// be debugged: a partner whose transmitter is misconfigured needs to know
// whether we rejected the issuer, the audience or the signature, and the
// registry exists to tell them.
//
// The disclosure that remains is "this deployment has a source for issuer X",
// which requires guessing an exact issuer URL to learn.
//
// # Content-Language
//
// MUST be present (§2.3). Our messages are English, so it is `en` -- but the
// header has to be there, because a transmitter is entitled to know what
// language it is being told off in.
func writeSSFError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Language", "en")
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

// ssfErrorCode maps a verification failure to a registered error code.
//
// Matching on the message rather than on typed errors, because internal/ssf
// returns one wrapped ErrNotVerified for every check -- deliberately, so no
// caller can branch on the reason and act differently. The mapping lives here,
// at the edge, where the only consequence is which registered code a
// transmitter is told.
func ssfErrorCode(err error) (code, description string) {
	m := err.Error()
	switch {
	case strings.Contains(m, "aud "):
		return errInvalidAudience, "the audience does not identify this recipient"
	case strings.Contains(m, "iss is"):
		return errInvalidIssuer, "the issuer does not match the configured source"
	case strings.Contains(m, "no key") || strings.Contains(m, "key material") ||
		strings.Contains(m, "JWKS") || strings.Contains(m, "jwks"):
		return errInvalidKey, "the token is not signed by a key this source publishes"
	case strings.Contains(m, "may not send"):
		return errAccessDenied, "this source is not permitted to send that event type"
	}
	// Everything else -- malformed, wrong typ, missing jti, expired, future
	// iat -- is a parsing or payload problem.
	return errInvalidRequest, "the token could not be validated"
}

// applySignals acts on every entry in a verified token.
//
// Returns the recorded action and detail, or "" for an internal failure. RFC
// 8417 §2.2 permits several entries describing one logical event, so this
// applies all of them inside the caller's transaction -- partial application is
// impossible because the transaction is.
//
// Actions are idempotent by nature: ending an already-ended session ends
// nothing further, so two entries that both imply revocation cost one
// revocation rather than two.
func (s *Server) applySignals(ctx context.Context, tx pgx.Tx,
	event ssf.ReceivedEvent, userID string) (action, detail string) {

	if userID == "" {
		// Normal. A transmitter sends events about people we have never seen,
		// and that is not an error -- but it IS recorded, because "forty events
		// about nobody" is how a misconfigured subject format announces itself.
		return "no_matching_user", event.Subject.Sub
	}

	revoked := false
	var reasons []string
	for _, typ := range event.Types {
		switch typ {
		case ssf.EventSessionRevoked:
			revoked = true
			reasons = append(reasons, "session revoked upstream")
		case ssf.EventCredentialChange:
			// Somebody else's credential change is a reason to end our sessions
			// too: the same person's authentication elsewhere has changed, and
			// a session predating that change was established under the old one.
			revoked = true
			reasons = append(reasons, "credential change upstream")
		case ssf.EventAssuranceChange:
			// A drop in assurance is not a revocation, and treating it as one
			// would sign people out for stepping down from a hardware key to a
			// password on a second device. Recorded; policy decides.
			reasons = append(reasons, "assurance level changed upstream")
		default:
			reasons = append(reasons, "no handler for "+typ)
		}
	}

	if !revoked {
		return "recorded", strings.Join(reasons, "; ")
	}
	n, err := store.TerminateSessions(ctx, tx, "", userID, store.ReasonSharedSignal)
	if err != nil {
		s.log.Error("terminating sessions from a shared signal", "err", err)
		return "", ""
	}
	return "sessions_revoked",
		strings.Join(reasons, "; ") + "; " + itoaInt(n.Sessions) + " session(s)"
}
