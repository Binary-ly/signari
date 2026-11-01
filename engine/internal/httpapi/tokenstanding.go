package httpapi

import (
	"context"
	"errors"
	"net/http"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// verifyAccepted verifies a token presented here, as this deployment's own and
// then, only when that says the issuer is another one, against the issuers it has
// retired: nearly every token is the deployment's own, and reading the aliases
// first was a statement on each of them.
func (s *Server) verifyAccepted(ctx context.Context, raw string) (*tokens.AccessTokenClaims, error) {
	claims, err := s.verifyPresented(ctx, []string{s.cfg.Issuer}, raw)
	if errors.Is(err, tokens.ErrWrongIssuer) {
		return s.verifyPresented(ctx, s.acceptedIssuers(ctx), raw)
	}
	return claims, err
}

// standing is what has become of an accepted token, read now. where names the
// place in the log, since the failure it logs is the database's and the answer
// given for it is that the token has ended.
func (s *Server) standing(ctx context.Context, claims *tokens.AccessTokenClaims, where string) store.TokenStanding {
	st, err := store.TokenStandingOf(ctx, s.db, claims)
	if err != nil {
		s.log.Error("reading what has become of a token", "where", where, "err", err,
			"correlation_id", correlationID(ctx))
	}
	return st
}

// endedDescription is what a resource server says of a token that has ended, and
// empty for one that has not.
func endedDescription(st store.TokenStanding) string {
	switch {
	case st.GrantRevoked:
		return "The authorization behind this token has been revoked"
	case st.JTIRevoked:
		return "The access token has been revoked"
	case st.SessionEnded:
		return "The session has ended"
	case st.HolderGone:
		return "The client or subject of this token is no longer active"
	}
	return ""
}

// exchangeRefusal is the refusal, under code, of a token offered in an exchange that
// has ended, and nil for one that has not. A dead credential must not become a live
// one: which says which of the tokens offered this is. RFC 8693 §2.2.2 wants
// invalid_request, and a Txn-Token's request goes by RFC 6749 §5.2.
func (s *Server) exchangeRefusal(ctx context.Context, claims *tokens.AccessTokenClaims, which, code string) *oauth.TokenError {
	st := s.standing(ctx, claims, which+" token")
	var why string
	switch {
	case st.GrantRevoked:
		why = "the authorization behind the " + which + " token has been revoked"
	case st.JTIRevoked:
		why = "the " + which + " token has been revoked"
	case st.SessionEnded:
		why = "the session behind the " + which + " token has ended"
	case st.HolderGone:
		why = "the client or subject of the " + which + " token is no longer active"
	default:
		return nil
	}
	return &oauth.TokenError{Code: code, Description: why, Status: http.StatusBadRequest}
}
