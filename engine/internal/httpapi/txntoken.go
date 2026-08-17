package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/txntoken"
)

// The Transaction Token Service.
//
// Reached at the ordinary token endpoint, because a Txn-Token request IS an RFC
// 8693 token exchange with a different `requested_token_type`. A separate
// endpoint would mean a second place that has to get client authentication,
// revocation checking and session liveness right.
//
// See internal/txntoken for what the format is and why it matters.

// handleTxnToken issues or replaces a Transaction Token.
func (s *Server) handleTxnToken(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	ctx := r.Context()

	if !c.MayExchange {
		// The same permission as any other exchange. A client that may not
		// exchange tokens must not be able to mint a credential that asserts a
		// user's identity to every service in the trust domain.
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "this client is not permitted to exchange tokens",
			Status:      http.StatusBadRequest})
		return
	}

	req := txntoken.Request{
		Audience:         firstForm(r, "audience"),
		Scope:            strings.Fields(firstForm(r, "scope")),
		SubjectToken:     firstForm(r, "subject_token"),
		SubjectTokenType: firstForm(r, "subject_token_type"),
		RequestContext:   jsonObjectForm(r, "request_context"),
		RequestDetails:   jsonObjectForm(r, "request_details"),
	}
	if err := req.Validate(); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: err.Error(), Status: http.StatusBadRequest})
		return
	}

	// The trust domain must be one this client is allowed to mint for. Without
	// this, any client with exchange permission mints tokens accepted by every
	// service in every trust domain the deployment serves.
	if !allowedAudience(c.ExchangeAudiences, req.Audience) {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_target",
			Description: "this client may not issue transaction tokens for that trust domain",
			Status:      http.StatusBadRequest})
		return
	}

	now := time.Now()
	var out txntoken.Claims

	switch req.SubjectTokenType {
	case txntoken.TokenType:
		// A REPLACEMENT: the next hop in a chain.
		prev, err := s.verifyTxnToken(req.SubjectToken)
		if err != nil {
			s.log.Info("txn-token replacement: subject token rejected", "err", err,
				"caller", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the presented transaction token is not valid",
				Status:      http.StatusBadRequest})
			return
		}
		// The trust domain cannot change mid-chain. A replacement that crossed
		// domains would carry authority granted in one into a place that never
		// granted it.
		if !strings.EqualFold(prev.Audience, req.Audience) {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_target",
				Description: "a replacement cannot change the trust domain",
				Status:      http.StatusBadRequest})
			return
		}
		out, err = txntoken.Replace(txntoken.Replacement{
			Previous: prev,
			// From CLIENT AUTHENTICATION, never the body. A workload that could
			// name itself is a workload that can name somebody else.
			Workload:       c.ClientID,
			Scope:          req.Scope,
			RequestContext: req.RequestContext,
		}, s.cfg.Issuer, now, txntoken.DefaultTTL)
		if err != nil {
			code := "invalid_grant"
			if strings.Contains(err.Error(), "widen") {
				code = "invalid_scope"
			}
			writeTokenError(w, &oauth.TokenError{Code: code,
				Description: err.Error(), Status: http.StatusBadRequest})
			return
		}

	default:
		// AN INITIAL REQUEST, from an access token at the edge.
		subject, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, s.acceptedIssuers(),
			req.SubjectToken)
		if err != nil {
			s.log.Info("txn-token: subject token rejected", "err", err,
				"caller", c.ClientID, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the subject token is not valid", Status: http.StatusBadRequest})
			return
		}
		// A revoked token, or one whose session has ended, must not become a
		// Txn-Token. Otherwise exchange laundered a dead credential into one
		// that every internal service will honour for the next five minutes --
		// and the internal services have no way to check.
		if revoked, rerr := store.JTIRevoked(ctx, s.db, subject.JTI); rerr != nil || revoked {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
				Description: "the subject token has been revoked",
				Status:      http.StatusBadRequest})
			return
		}
		if subject.SessionID != "" {
			live, serr := store.SessionLive(ctx, s.db, subject.SessionID)
			if serr != nil || !live {
				writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
					Description: "the session behind the subject token has ended",
					Status:      http.StatusBadRequest})
				return
			}
		}

		// Scope is bounded by what the SUBJECT TOKEN actually carries, read
		// from the verified token rather than the form. Reading it from the
		// request would let a caller describe its own token as carrying
		// anything, and the ceiling would be a number the attacker chose.
		had := strings.Fields(subject.Scope)
		for _, want := range req.Scope {
			if !containsString(had, want) {
				writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
					Description: "the subject token does not carry " + want,
					Status:      http.StatusBadRequest})
				return
			}
		}

		txn, err := newSID()
		if err != nil {
			writeTokenError(w, &oauth.TokenError{Code: "server_error",
				Status: http.StatusInternalServerError})
			return
		}
		out = txntoken.Claims{
			Issuer:             s.cfg.Issuer,
			IssuedAt:           now.Unix(),
			Expiry:             now.Add(txntoken.DefaultTTL).Unix(),
			Audience:           req.Audience,
			Transaction:        txn,
			Subject:            subject.Subject,
			RequestingWorkload: c.ClientID,
			Scope:              strings.Join(req.Scope, " "),
			TransactionContext: req.RequestDetails,
			RequestContext:     req.RequestContext,
		}
		// A Txn-Token must never outlive the credential it was derived from.
		if subject.Expiry > 0 && out.Expiry > subject.Expiry {
			out.Expiry = subject.Expiry
		}
	}

	key, err := s.cfg.Keys.Active(keys.ES256)
	if err != nil {
		for _, alg := range s.cfg.Keys.Algorithms() {
			if k, e := s.cfg.Keys.Active(alg); e == nil {
				key, err = k, nil
				break
			}
		}
	}
	if err != nil {
		s.log.Error("txn-token: no active key", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	// Explicitly typed. A resource server that accepts at+jwt and txntoken+jwt
	// without checking would let one be presented as the other, and they carry
	// different authority -- RFC 8725's explicit-typing rule exists for exactly
	// this confusion.
	signed, err := tokens.NewSigner(key).SignJSON(out, txntoken.Typ)
	if err != nil {
		s.log.Error("txn-token: signing", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "txntoken.issued", OrgID: c.OrgID, SubjectID: out.Subject,
		ClientID: c.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"txn": out.Transaction, "trust_domain": out.Audience,
			"scope": out.Scope, "replacement": req.SubjectTokenType == txntoken.TokenType,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(txntoken.NewResponse(signed))
}

// verifyTxnToken checks a presented Txn-Token and returns its claims.
func (s *Server) verifyTxnToken(raw string) (txntoken.Claims, error) {
	var c txntoken.Claims
	// Verified with the typ REQUIRED to be txntoken+jwt. Accepting an access
	// token here would let one be replayed as a transaction token, which is the
	// confusion the distinct typ exists to prevent.
	if err := tokens.VerifyTypedJSON(s.cfg.Keys, s.acceptedIssuers(), raw,
		txntoken.Typ, &c); err != nil {
		return c, err
	}
	if c.Expiry > 0 && time.Now().Unix() >= c.Expiry {
		return c, fmt.Errorf("the transaction token has expired")
	}
	return c, nil
}

func firstForm(r *http.Request, key string) string {
	if v := r.PostForm[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// jsonObjectForm reads a JSON object parameter, or nil.
//
// A malformed one is dropped rather than refused: request context is
// RECOMMENDED, not required, and refusing the whole transaction because a
// gateway sent slightly wrong JSON in an optional field is the wrong trade.
func jsonObjectForm(r *http.Request, key string) map[string]any {
	raw := firstForm(r, key)
	if raw == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func allowedAudience(allowed []string, want string) bool {
	if len(allowed) == 0 {
		// No allow-list configured means none may be minted. An empty list is
		// not permission for everything -- that reading turns a forgotten
		// configuration into an open door.
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
