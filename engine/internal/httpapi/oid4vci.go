package httpapi

import (
	"errors"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
)

// OID4VCI 1.0 §6: the Pre-Authorized Code grant at the token endpoint.
//
// # Why this grant does not resolve its client from the request
//
// §6.1: "For the Pre-Authorized Code Grant Type, authentication of the Client is
// OPTIONAL, as described in Section 3.2.1 of [RFC6749], and, as a consequence,
// the client_id parameter is only needed when a form of Client Authentication
// that relies on this parameter is used."
//
// So a conformant wallet redeems with `grant_type` and `pre-authorized_code` and
// nothing else. There is still a client, because a token needs an audience,
// scopes and a lifetime — it is just chosen when the OFFER is minted, by the
// operator who knows which credential issuer the offer is for, and read back
// here from the code.
//
// That is also the stronger position. If the wallet named the client, it would
// be choosing which client's scopes its own token carries.

// handlePreAuthorizedCodeGrant redeems a pre-authorized code for an access token.
func (s *Server) handlePreAuthorizedCodeGrant(w http.ResponseWriter, r *http.Request,
	req oauth.TokenRequest) {
	ctx := r.Context()

	vreq := oid4vci.TokenRequest{
		GrantType: req.GrantType,
		Code:      r.PostForm.Get("pre-authorized_code"),
		TxCode:    r.PostForm.Get("tx_code"),
	}

	stored, err := store.LookupPreAuthorizedCode(ctx, s.db, store.HashToken(vreq.Code))
	if err != nil && !errors.Is(err, store.ErrPreAuthUnknown) {
		s.log.Error("looking up a pre-authorized code", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	var sc *oid4vci.StoredCode
	if stored != nil {
		sc = &stored.StoredCode
	}
	if verr := oid4vci.ValidateTokenRequest(vreq, sc, time.Now()); verr != nil {
		// invalid_grant for every case, whatever the reason.
		//
		// The reasons are genuinely different — unknown code, spent code, expired
		// code, missing transaction code, too many guesses — and the description
		// says which, because a wallet has to render something to a person who is
		// standing there wondering why their credential did not arrive. What it
		// does NOT do is vary the error CODE, so a redemption attempt against a
		// code that never existed is indistinguishable from one against a spent
		// code to anything parsing the response programmatically.
		s.log.Info("pre-authorized code refused", "err", verr,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: verr.Error(), Status: http.StatusBadRequest})
		return
	}

	// A wallet that DID send a client_id must have sent the right one.
	//
	// §6.1 makes the parameter unnecessary, not free: a request naming a
	// different client than the offer was issued to means the wallet and the
	// issuer disagree about what is being redeemed, and proceeding would resolve
	// that disagreement silently in the offer's favour.
	if req.ClientID != "" && req.ClientID != stored.ClientID {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "this pre-authorized code was issued for a different client",
			Status:      http.StatusBadRequest})
		return
	}

	c, lerr := s.lookupClient(ctx, stored.ClientID)
	if lerr != nil || c == nil {
		// The offer names a client that no longer exists. Refusing is the only
		// safe answer: minting without one would produce a token whose audience
		// and lifetime nothing decided.
		s.log.Error("a pre-authorized code names a client that no longer exists",
			"client_id", stored.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "the client this offer was issued for no longer exists",
			Status:      http.StatusBadRequest})
		return
	}

	// Registered for this grant. The central gate in handleToken cannot cover
	// this one, because it runs after the client is resolved from the request and
	// this grant resolves its client from the offer instead.
	//
	// The offer's own minting checks this too, so reaching here means the
	// registration was withdrawn after the offer went out — which is exactly when
	// refusing matters.
	if !c.AllowsGrantType(oid4vci.GrantType) {
		s.log.Info("pre-authorized code refused: the client is no longer registered "+
			"for the grant", "client_id", c.ClientID, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "this client is not registered for the pre-authorized code grant",
			Status:      http.StatusBadRequest})
		return
	}

	// Confidential clients still authenticate.
	//
	// §6.1 says client authentication is OPTIONAL for this grant, which settles
	// whether the SPEC requires it, not whether a client registered as
	// confidential may skip it. A confidential client is one that holds a secret;
	// letting a grant type waive that would make "confidential" a property the
	// caller can opt out of by choosing a grant.
	//
	// Offers are minted for public clients in the ordinary wallet case, so this
	// branch is not the path a wallet takes.
	if c.Type == "confidential" {
		if aerr := s.authenticateConfidentialClient(ctx, r, c, req.ClientSecret); aerr != nil {
			s.log.Info("client authentication failed redeeming a pre-authorized code",
				"client_id", c.ClientID, "err", aerr, "correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
				Description: "client authentication failed", Status: http.StatusUnauthorized})
			return
		}
	}

	// The transaction code, compared in constant time against the stored hash.
	//
	// A wrong one charges an attempt and does NOT spend the offer. That ordering
	// is the point: claiming first would mean one wrong guess destroys the
	// holder's credential, which turns a shoulder-surfing defence into a denial
	// of service that anybody who photographed the QR code can perform.
	if stored.RequiresTxCode && !stored.CheckTxCode(store.HashToken(vreq.TxCode)) {
		if rerr := store.RecordTxCodeFailure(ctx, s.db, stored.ID); rerr != nil {
			s.log.Error("recording a transaction code failure", "err", rerr)
		}
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: stored.OrgID, SubjectID: stored.UserID,
			ClientID: c.ClientID, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"via": "oid4vci", "reason": "bad_tx_code",
				"attempts": stored.Attempts + 1, "limit": oid4vci.MaxTxCodeAttempts},
		})
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "the transaction code is incorrect", Status: http.StatusBadRequest})
		return
	}

	// Single use, claimed atomically, and only once everything else has passed.
	if cerr := store.ClaimPreAuthorizedCode(ctx, s.db, stored.ID); cerr != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: cerr.Error(), Status: http.StatusBadRequest})
		return
	}

	// Tokens, through the same path every other grant uses.
	//
	// No session id and no nonce: a pre-authorized code is issued out of band, so
	// there is no browser session behind it. What the credential endpoint reads
	// from the access token is its subject and its scope, which mintSet supplies.
	//
	// Two scopes are withheld, and both follow from there being no session:
	//
	//   - `openid` asks for an authentication statement about a person. Nothing
	//     here authenticated anybody — the operator vouched for the holder when
	//     they minted the offer, at some earlier time, by some means this server
	//     never saw. An id_token would assert an `auth_time` and an `amr` that
	//     did not happen.
	//   - `offline_access` asks for a refresh token, whose whole purpose is to
	//     outlive the request. A refresh family is anchored to a session so that
	//     ending the session ends the tokens; anchored to nothing, it would be a
	//     credential with no way to revoke it short of the client.
	//
	// Refused rather than silently dropped where a caller could have asked for
	// them — but a wallet cannot ask, since this grant carries no scope
	// parameter, so there is nobody to tell. Filtering is the whole of it.
	scopes := make([]string, 0, len(c.Scopes))
	for _, sc := range c.Scopes {
		if sc == "openid" || sc == "offline_access" {
			continue
		}
		scopes = append(scopes, sc)
	}
	tx, terr := s.db.Begin(ctx)
	if terr != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	resp, _, merr := s.mintSet(ctx, tx, c, stored.OrgID, stored.UserID, "", "",
		scopes, nil, "")
	if merr != nil {
		s.log.Error("minting tokens for a pre-authorized code grant", "err", merr,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: audit.EventLoginSucceeded, OrgID: stored.OrgID, SubjectID: stored.UserID,
		ClientID: c.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"via": "oid4vci",
			"credential_configuration_ids": stored.ConfigurationIDs},
	})

	writeJSON(w, http.StatusOK, resp)
}
