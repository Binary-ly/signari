package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/store"
)

// brokerRefreshMargin is how long an upstream token has to have left to be handed over
// as it is. An application given one about to end would fail on its next call.
const brokerRefreshMargin = 30 * time.Second

// handleBrokerToken hands an application the token an upstream provider gave the person
// the access token names (8.17), renewing it first if it is about to end. The scope is
// per provider, `broker.<slug>`, so being allowed a person's GitHub is not being allowed
// their Google, and an operator grants it to a client as any other.
func (s *Server) handleBrokerToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	slug := r.PathValue("slug")
	claims, ok := s.acceptedToken(w, r, "broker."+slug, "broker token")
	if !ok {
		return
	}
	person, isPerson := store.CanonicalUUID(claims.Subject)
	if !isPerson {
		writeError(w, http.StatusForbidden, "invalid_request", "this token names no person")
		return
	}
	upstream, err := s.loadIdentityProvider(ctx, slug)
	if err != nil || !upstream.StoreTokens {
		writeError(w, http.StatusNotFound, "not_found", "no tokens are kept at that provider")
		return
	}
	held, expires, err := store.FederatedTokens(ctx, s.db, s.root, upstream.ID, person)
	if errors.Is(err, store.ErrNoFederatedTokens) {
		writeError(w, http.StatusNotFound, "not_found", "no tokens are kept at that provider")
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "reading a provider's tokens", "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusInternalServerError, "server_error", "the token could not be read")
		return
	}

	if expires != nil && time.Until(*expires) < brokerRefreshMargin {
		if held.RefreshToken == "" {
			writeError(w, http.StatusConflict, "reauthentication_required",
				"the person has to sign in at the provider again")
			return
		}
		fresh, rerr := upstream.RefreshTokens(ctx, s.outboundClient(federationTimeout), held.RefreshToken)
		if rerr != nil {
			s.log.WarnContext(ctx, "a provider would not renew a token", "provider", slug, "err", rerr,
				"correlation_id", correlationID(ctx))
			writeError(w, http.StatusConflict, "reauthentication_required",
				"the person has to sign in at the provider again")
			return
		}
		if err := store.KeepFederatedTokens(ctx, s.db, s.root, upstream.ID, person, upstream.OrgID, *fresh); err != nil {
			s.log.ErrorContext(ctx, "keeping a renewed token", "err", err, "correlation_id", correlationID(ctx))
			writeError(w, http.StatusInternalServerError, "server_error", "the token could not be kept")
			return
		}
		held = fresh
		expires = nil
		if fresh.ExpiresIn > 0 {
			at := time.Now().Add(time.Duration(fresh.ExpiresIn) * time.Second)
			expires = &at
		}
	}

	// A credential at somebody else's service left this server, so it is on the
	// record, as a token this server issued is not.
	s.auditDetached(ctx, audit.Event{Type: "federation.token_read", OrgID: upstream.OrgID, SubjectID: person,
		ClientID: claims.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"provider": slug}})

	out := map[string]any{"access_token": held.AccessToken, "token_type": held.TokenType}
	if held.Scope != "" {
		out["scope"] = held.Scope
	}
	if expires != nil {
		out["expires_in"] = int(time.Until(*expires).Seconds())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
