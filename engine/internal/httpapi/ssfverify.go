package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// authenticateStreamClient authenticates a receiver as its stream's OAuth client,
// over the Authorization header (Basic) or the connection (mutual-TLS), and
// answers for itself when that fails. The bodies here are JSON, so the
// form-carried methods -- client_secret_post, private_key_jwt -- have nowhere to
// put their parameters and are not offered; a stream is configured on a client
// that authenticates one of these two ways.
func (s *Server) authenticateStreamClient(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context()
	creds, cerr := oauth.ParseClientCredentials(r.Header, nil)
	if cerr != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", cerr.Description)
		return "", false
	}
	c, err := s.lookupClient(ctx, creds.ClientID)
	if err != nil || c == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return "", false
	}
	if c.Type != "confidential" {
		writeError(w, http.StatusUnauthorized, "invalid_client",
			"a security event stream requires a confidential client")
		return "", false
	}
	if aerr := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); aerr != nil {
		s.log.Info("ssf receiver authentication failed", "client_id", creds.ClientID, "err", aerr,
			"correlation_id", correlationID(ctx))
		writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return "", false
	}
	return creds.ClientID, true
}

// handleSSFVerify is SSF 1.0 §8.1.4.2: a receiver whose stream has been quiet asks
// for an event, to tell a calm stream from a broken one. The event goes the way
// every other does, the worker's retries or the next poll, because that way is what
// is being tested. So 204 means it is queued, which is all the section says it means:
// "only that the Event Transmitter has transmitted the event or will do so at some
// point in the future" (specs/ssf-1_0.txt:3268-3270).
func (s *Server) handleSSFVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID, ok := s.authenticateStreamClient(w, r)
	if !ok {
		return
	}

	var req struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPollBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid JSON")
		return
	}
	if req.StreamID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "stream_id is required")
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	switch err := store.QueueVerification(ctx, tx, clientID, req.StreamID, req.State); {
	case errors.Is(err, store.ErrStreamUnknown):
		writeError(w, http.StatusNotFound, "invalid_request", "this client has no stream with that id")
		return
	case errors.Is(err, store.ErrStreamDisabled):
		writeError(w, http.StatusBadRequest, "invalid_request",
			"the stream is disabled, so nothing can be sent over it")
		return
	case errors.Is(err, store.ErrVerificationTooSoon):
		w.Header().Set("Retry-After", strconv.Itoa(int(store.MinVerificationInterval.Seconds())))
		writeError(w, http.StatusTooManyRequests, "slow_down", "a verification was asked for too recently")
		return
	case err != nil:
		s.log.Error("queueing a verification event", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.log.Error("queueing a verification event", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
