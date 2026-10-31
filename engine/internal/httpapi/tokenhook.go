package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/provider"
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

// issueAccessToken signs an access token and answers what the client is given: the
// token itself, or for a client set to opaque, a handle that stands for it. Through q,
// so a handle stored in a grant's transaction goes with it if the grant is undone.
//
// The subject, and whoever is acting for them, are put as the client knows them here,
// so no grant can forget to. A delegation further down the chain keeps what it said.
func issueAccessToken(ctx context.Context, q store.SubjectDB, client *clients.Client, signer *tokens.Signer,
	c tokens.AccessTokenClaims) (string, error) {
	var err error
	if c.Subject, err = subjectFor(ctx, q, client, c.Subject); err != nil {
		return "", err
	}
	if c.Act, err = actorFor(ctx, q, client, c.Act); err != nil {
		return "", err
	}
	signed, err := signAccessToken(ctx, signer, c)
	if err != nil || client.AccessFormat != "opaque" {
		return signed, err
	}
	return store.NewOpaqueToken(ctx, q, client.OrgID, client.ClientID, signed, time.Unix(c.Expiry, 0))
}

// subjectFor is what a client calls a subject: the person's id, or for a client set to
// pairwise, what its sector knows them by. A client's own token is left naming the client.
func subjectFor(ctx context.Context, q store.SubjectDB, client *clients.Client, subject string) (string, error) {
	if client.SubjectType != "pairwise" || subject == client.ClientID {
		return subject, nil
	}
	return store.PairwiseSubject(ctx, q, client.OrgID, client.Sector, subject)
}

// actorFor is an actor claim as a client knows it. A copy, because one actor goes into
// both of a grant's tokens.
func actorFor(ctx context.Context, q store.SubjectDB, client *clients.Client, act *tokens.Actor) (*tokens.Actor, error) {
	if act == nil {
		return nil, nil
	}
	subject, err := subjectFor(ctx, q, client, act.Subject)
	if err != nil {
		return nil, err
	}
	named := *act
	named.Subject = subject
	return &named, nil
}

// verifyPresented verifies what a caller presented as an access token, whichever form
// a client was given it in. Every path that takes one comes through here, so a client
// set to opaque has its tokens taken everywhere a JWT is. A handle that opens nothing
// goes to the verifier as it came, and is refused there like anything else. A pairwise
// subject is read back here too, so whatever takes a token sees the person, and one
// whose person has gone is no token at all.
func (s *Server) verifyPresented(ctx context.Context, issuers []string, raw string) (*tokens.AccessTokenClaims, error) {
	return s.verifyPresentedIn(ctx, s.db, issuers, raw)
}

// verifyPresentedIn is verifyPresented reading through q, for a caller holding a
// transaction, where a second connection from the pool is how a pool deadlocks.
func (s *Server) verifyPresentedIn(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, issuers []string, raw string) (*tokens.AccessTokenClaims, error) {
	if strings.HasPrefix(raw, store.OpaqueTokenPrefix) {
		signed, err := store.OpenOpaqueToken(ctx, q, raw)
		switch {
		case err == nil:
			raw = signed
		case !errors.Is(err, store.ErrNoOpaqueToken):
			s.log.Error("reading an opaque access token", "err", err)
		}
	}
	claims, err := tokens.VerifyAccessTokenAny(s.cfg.Keys, issuers, raw)
	if err != nil {
		return nil, err
	}
	person, err := store.PersonNamedBy(ctx, q, claims.ClientID, claims.Subject)
	if err != nil {
		return nil, err
	}
	if person != claims.Subject {
		claims.Pairwise, claims.Subject = claims.Subject, person
	}
	return claims, nil
}

// askHook asks a hook's provider about something this engine has said yes to. A row
// that will not load refuses, as at the token endpoint: the operator registered something,
// and it is not for this process to decide it can be ignored. Through q, for a caller
// holding a transaction: the call is bounded by the provider's timeout, and it is the one
// thing a sign-in waits on.
func (s *Server) askHook(ctx context.Context, q dbReader, orgID string, hook provider.Hook, req any) store.TokenHookResult {
	res, err := store.ConsultHook(ctx, q, s.root, s.outboundClient, s.log, orgID, hook, req)
	if err != nil {
		s.log.Error("consulting a provider", "hook", string(hook), "err", err,
			"correlation_id", correlationID(ctx))
		return store.TokenHookResult{Vetoed: true, Reason: "the provider could not be read"}
	}
	return res
}

// recordHookRefusal logs and audits a provider's refusal. The reason stays here: it was
// written by somebody outside this deployment, and is not for the person refused.
func (s *Server) recordHookRefusal(ctx context.Context, hook provider.Hook, orgID, subject, clientID, reason string) {
	s.log.Warn("a provider refused", "hook", string(hook), "client_id", clientID, "reason", reason,
		"correlation_id", correlationID(ctx))
	s.auditDetached(ctx, audit.Event{Type: "provider.refused", OrgID: orgID, SubjectID: subject,
		ClientID: clientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"hook": string(hook), "reason": reason}})
}

// userCreateRefused asks the user_create provider about an account about to be made by
// somebody other than an operator. source is signup or federation.
func (s *Server) userCreateRefused(ctx context.Context, q dbReader, orgID, email, source string) (string, bool) {
	res := s.askHook(ctx, q, orgID, provider.HookUserCreate,
		store.UserCreateHookRequest{OrgID: orgID, Email: email, Source: source})
	return res.Reason, res.Vetoed
}

// recordFederatedRefusal is recordHookRefusal for the federated callback, where the name
// of this package is taken by the identity provider.
func (s *Server) recordFederatedRefusal(ctx context.Context, orgID, reason string) {
	s.recordHookRefusal(ctx, provider.HookUserCreate, orgID, "", "", reason)
}

// clientAccessRefused asks the client_access provider about a person reaching an
// application the access policy has let them reach, in AuthZEN's shape, so what answers
// the authorize hook can answer this.
func (s *Server) clientAccessRefused(ctx context.Context, orgID, clientID, userID string) bool {
	res := s.askHook(ctx, s.db, orgID, provider.HookClientAccess, authzen.Request{
		Subject: authzen.Subject{Type: "user", ID: userID}, Action: authzen.Action{Name: "access"},
		Resource: authzen.Resource{Type: "client", ID: clientID}})
	if res.Vetoed {
		s.recordHookRefusal(ctx, provider.HookClientAccess, orgID, userID, clientID, res.Reason)
	}
	return res.Vetoed
}

// consultTokenHook asks the token_issue provider about an issuance this engine
// has already decided to make. Before the grant's transaction opens, because
// the call may take the provider's whole timeout. A veto or a fault is
// answered here and ok is false; otherwise the context carries what the
// provider contributed. A client whose organisation has none has told us so.
func (s *Server) consultTokenHook(ctx context.Context, w http.ResponseWriter, c *clients.Client,
	req store.TokenHookRequest) (context.Context, bool) {
	if req.OrgID == c.OrgID && !c.HasTokenHook {
		return ctx, true
	}
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
