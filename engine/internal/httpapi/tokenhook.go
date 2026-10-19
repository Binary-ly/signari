package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The operator's token_issue provider, at every grant (2.03).
//
// It was consulted on authorization_code redemption only, so a provider that
// vetoed a person went on seeing them issued tokens by refresh, device, CIBA,
// jwt-bearer, exchange and the rest, and the claims it was allowed to
// contribute were filtered and then thrown away. Every grant now asks through
// consultTokenHook before its transaction opens, and every access token is
// signed through signAccessToken, which carries what the provider contributed.
// TestEveryGrantConsultsTheTokenHook and TestEveryAccessTokenIsSignedThroughOneHelper
// keep both true as grants are added.

type hookClaimsKey struct{}

// withHookClaims carries a provider's contributed claims to the mint. On the
// context, as the DPoP thumbprint is, because every grant's mint would
// otherwise thread a value most issuances never set.
func withHookClaims(ctx context.Context, claims map[string]any) context.Context {
	if len(claims) == 0 {
		return ctx
	}
	return context.WithValue(ctx, hookClaimsKey{}, claims)
}

func hookClaimsFrom(ctx context.Context) map[string]any {
	claims, _ := ctx.Value(hookClaimsKey{}).(map[string]any)
	return claims
}

// signAccessToken is the one way an access token is signed. It adds the claims
// the token_issue provider contributed for this issuance; a claim mapper's
// value wins on the same name, being the operator's own configuration, and
// tokens.AccessTokenClaims refuses either taking a protocol claim.
func signAccessToken(ctx context.Context, signer *tokens.Signer, c tokens.AccessTokenClaims) (string, error) {
	if contributed := hookClaimsFrom(ctx); len(contributed) > 0 {
		merged := make(map[string]any, len(contributed)+len(c.Extra))
		for k, v := range contributed {
			merged[k] = v
		}
		for k, v := range c.Extra {
			merged[k] = v
		}
		c.Extra = merged
	}
	return signer.SignJSON(c, tokens.TypAccessToken)
}

// consultTokenHook asks the token_issue provider about an issuance this engine
// has already decided to make. Before the grant's transaction opens, because
// the call may take the provider's whole timeout. A veto or a fault is
// answered here and ok is false; otherwise the context carries what the
// provider contributed.
func (s *Server) consultTokenHook(ctx context.Context, w http.ResponseWriter,
	req store.TokenHookRequest) (context.Context, bool) {
	hook, err := store.ConsultTokenProvider(ctx, s.db, s.root, s.outboundClient, s.log, req.OrgID, req)
	if err != nil {
		s.log.Error("consulting the token provider", "err", err, "grant_type", req.Grant)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return ctx, false
	}
	if hook.Vetoed {
		s.refuseVetoedIssuance(ctx, w, req, hook.Reason)
		return ctx, false
	}
	return withHookClaims(ctx, hook.Claims), true
}

// refuseVetoedIssuance answers and records a veto. The provider's reason goes
// to the log and the audit trail, never to the client: it is written by
// somebody outside this deployment and must not become part of an OAuth error
// a stranger reads.
func (s *Server) refuseVetoedIssuance(ctx context.Context, w http.ResponseWriter,
	req store.TokenHookRequest, reason string) {
	s.recordVeto(ctx, req, reason)
	writeTokenError(w, &oauth.TokenError{
		Code:        "access_denied",
		Description: "this authorization was refused",
		Status:      http.StatusForbidden,
	})
}

// recordVeto logs and audits a veto, for a path with no response to write.
func (s *Server) recordVeto(ctx context.Context, req store.TokenHookRequest, reason string) {
	s.log.Warn("token issuance vetoed by the operator's provider",
		"client_id", req.ClientID, "grant_type", req.Grant, "reason", reason,
		"correlation_id", correlationID(ctx))
	// A person's id; a client's own token names the client, which the record
	// carries as its client already.
	subject := ""
	if _, perr := uuid.Parse(req.Subject); perr == nil {
		subject = req.Subject
	}
	s.auditDetached(ctx, audit.Event{
		Type: "token.vetoed", OrgID: req.OrgID, SubjectID: subject,
		ClientID: req.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"reason": reason, "grant_type": req.Grant},
	})
}
