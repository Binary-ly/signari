package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/federation"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// handleJWTBearerGrant implements RFC 7523 §2.1.
//
// A party we trust signs a statement about a subject; the client presents it;
// we mint our own token for the local account that subject is linked to. It is
// what workload identity federation runs on -- a CI job or a pod trades its
// platform-issued JWT for our token instead of holding a long-lived secret.
//
// # The order of operations is the security design
//
// The assertion has to be parsed BEFORE it is verified, because `iss` is what
// selects the key that verifies it. That is unavoidable and it is the sharp edge:
// anything read from the unverified parse is attacker-controlled. So exactly one
// value is taken from it -- the issuer, used only to look up a trust anchor -- and
// every claim that decides anything is read back out of the VERIFIED payload
// afterwards.
// assertionRefused is the ONE description every post-authentication refusal
// carries.
//
// # Why they are all the same sentence
//
// The causes are genuinely different -- unknown issuer, disabled provider,
// unlinked subject, deactivated user, unmet obligation, replay -- and telling
// them apart is a capability the caller must not have:
//
//   - The issuer is resolved BEFORE any signature is checked, because `iss`
//     selects the verification key. So a distinct "issuer not trusted" reply lets
//     anyone with client credentials enumerate the deployment's trusted issuers
//     using assertions that are not signed at all.
//   - A distinct "no active account" reply enumerates which subjects are linked,
//     and separating "not linked" from "disabled" says which accounts an
//     administrator has turned off.
//
// The most deployed implementation of this grant returns its internal exception
// message to the client, so it answers all six questions. This returns one
// sentence and logs the real reason against a correlation id.
const assertionRefused = "the assertion could not be used to obtain a token"

func (s *Server) handleJWTBearerGrant(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	ctx := r.Context()

	assertion := firstForm(r, "assertion")
	if assertion == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "assertion is required", Status: http.StatusBadRequest})
		return
	}

	// A public client cannot prove it is the client this trust was granted to, so
	// anyone who observes an assertion could spend it. Same reasoning as token
	// exchange, and the same answer.
	if c.Type != "confidential" {
		writeTokenError(w, &oauth.TokenError{Code: "unauthorized_client",
			Description: "the jwt-bearer grant requires a confidential client",
			Status:      http.StatusBadRequest})
		return
	}

	// Step one: the issuer, and NOTHING else, from an unverified parse.
	untrustedIssuer, err := oauth.PeekAssertionIssuer(assertion)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	provider, err := store.LoadJWTBearerProvider(ctx, s.db, c.OrgID, untrustedIssuer)
	if err != nil {
		// One answer for "not trusted", "disabled", "not opted in" and
		// "ambiguous". The client learns that the grant failed, not which
		// issuers this deployment trusts -- that list is a map of who can be
		// impersonated if one of them is ever compromised.
		s.log.Info("jwt-bearer: no usable trusted issuer",
			"issuer", untrustedIssuer, "client_id", c.ClientID,
			"err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	// Step one-and-a-half: may THIS client use THIS provider?
	//
	// Two gates already passed — the provider is opted in to the grant, and the
	// client is registered for it — and neither relates the two. In an
	// organisation trusting both a CI platform and a Kubernetes cluster, a client
	// that exists to let one pipeline reach one API could otherwise spend a pod's
	// service-account token. Nothing crosses a tenant boundary and it is still
	// authority nobody granted.
	//
	// Refused with the SAME sentence as every other failure, deliberately. A
	// distinct "this client may not use that provider" would confirm that the
	// named issuer is trusted here, which is the enumeration the shared message
	// exists to prevent — and it would confirm it to a caller who has just been
	// told they may not use it.
	if !c.MayUseAssertionsFrom(provider.Slug) {
		s.log.Info("jwt-bearer: client is not paired with this provider",
			"client_id", c.ClientID, "provider", provider.Slug,
			"permitted", c.JWTBearerProviders, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	// Step two: the signature, against that provider's published keys only.
	hc := &http.Client{Timeout: federationTimeout}
	payload, err := federation.VerifyAssertion(ctx, hc, &s.assertionKeys, *provider, assertion)
	if err != nil {
		s.log.Info("jwt-bearer: assertion did not verify",
			"provider", provider.Slug, "client_id", c.ClientID,
			"err", err, "correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	// Step three: every claim, re-read from the verified bytes.
	var claims oauth.AssertionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}
	// The verified issuer must be the provider we selected. The payload that was
	// peeked at and the payload that was verified are the same bytes today, so
	// this cannot currently differ -- it is here because "cannot currently
	// differ" is a property of code above, and a refactor that separates
	// selection from verification would otherwise silently trust the wrong
	// anchor.
	if claims.Issuer != provider.Issuer() {
		s.log.Warn("jwt-bearer: verified issuer differs from the selected provider",
			"verified", claims.Issuer, "selected", provider.Issuer(),
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}
	if terr := oauth.ValidateAssertionClaims(claims, s.assertionAudiences(), time.Now()); terr != nil {
		// The per-rule descriptions are precise and stay in the log. They are not
		// returned: "the assertion names more than one audience" and "the
		// assertion has no jti" describe the CALLER's own token, which is
		// harmless, but "issued more than 1h0m0s ago" and the audience rules also
		// describe this deployment's policy, and the whole set is a probe surface
		// for free. One sentence out, the detail in the log.
		s.log.Info("jwt-bearer: assertion claims refused",
			"provider", provider.Slug, "reason", terr.Description,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	// Step four: the local account, which must still be allowed to sign in.
	userID, orgID, err := store.FindActiveFederatedUser(ctx, s.db, provider.ID, claims.Subject)
	if err != nil {
		s.log.Info("jwt-bearer: no active linked account",
			"provider", provider.Slug, "err", err,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}
	if orgID != c.OrgID {
		// The provider, the account and the client must all belong to one
		// organisation. Without this a client in tenant A could spend an
		// assertion from tenant B's trusted issuer and receive a token for
		// tenant B's user -- a cross-tenant escalation assembled entirely out of
		// individually valid pieces.
		s.log.Warn("jwt-bearer: cross-organisation attempt",
			"client_org", c.OrgID, "account_org", orgID, "provider", provider.Slug,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	// Step five: replay. Above RFC 7523, which makes this optional.
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.ClaimAssertionJTI(ctx, tx, provider.ID, claims.JTI, claims.Expiry); err != nil {
		if !errors.Is(err, store.ErrAssertionReplayed) {
			// The database could not answer. Reporting that as a replay tells the
			// client something false and tells whoever reads the log that they are
			// under attack, which is how an outage becomes an incident response.
			s.log.Error("jwt-bearer: could not record the assertion identifier",
				"provider", provider.Slug, "err", err,
				"correlation_id", correlationID(ctx))
			writeTokenError(w, &oauth.TokenError{Code: "server_error",
				Status: http.StatusInternalServerError})
			return
		}
		s.log.Warn("jwt-bearer: assertion replay refused",
			"provider", provider.Slug, "client_id", c.ClientID,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: assertionRefused, Status: http.StatusBadRequest})
		return
	}

	scopes := c.Scopes
	if raw := firstForm(r, "scope"); raw != "" {
		scopes = splitScopes(raw)
		if unknown := c.UnknownScopes(scopes); len(unknown) > 0 {
			writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
				Description: "client is not registered for scope " + unknown[0],
				Status:      http.StatusBadRequest})
			return
		}
	}
	// `openid` asks us to state that WE authenticated this person. We did not --
	// a third party did, and what `acr` and `amr` should then say is a question
	// RFC 7523 does not answer and this engine has not decided. Refused with the
	// reason rather than quietly issuing an ID token whose authentication claims
	// would be invented.
	if containsScope(scopes, "openid") {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_scope",
			Description: "openid is not available to the jwt-bearer grant: the " +
				"authentication was performed by the assertion's issuer, not here",
			Status: http.StatusBadRequest})
		return
	}

	alg := keys.Algorithm(c.IDTokenAlg)
	key, err := s.cfg.Keys.Active(alg)
	if err != nil {
		s.log.Error("no active key for jwt-bearer", "alg", alg, "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}
	jti, err := newSID()
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	certThumb := ""
	if c.TLSBoundTokens {
		certThumb = certThumbprintFrom(ctx)
	}
	jkt := dpopThumbprintFrom(ctx)

	now := time.Now()
	at, err := tokens.NewSigner(key).SignJSON(tokens.AccessTokenClaims{
		Issuer:   s.cfg.Issuer,
		Subject:  userID,
		Audience: []string{c.ClientID},
		Expiry:   now.Add(tokens.DefaultAccessTokenTTL).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		Cnf:      bindingFor(jkt, certThumb),
		ClientID: c.ClientID,
		Scope:    joinScopes(scopes),
		// No SessionID. There is no browser session behind this: nothing was
		// signed in and nothing can be signed out. Inventing one would make
		// logout appear to cover a token it cannot reach.
	}, tokens.TypAccessToken)
	if err != nil {
		s.log.Error("signing jwt-bearer token", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		// Committed AFTER the token is minted but BEFORE it is written, so a
		// failure here means no token reaches the client and the replay record
		// rolls back with it. The alternative -- commit first -- would burn the
		// jti on a request that returned an error, and the caller's retry would
		// be refused as a replay.
		s.log.Error("committing jwt-bearer replay record", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error", Status: http.StatusInternalServerError})
		return
	}

	// No refresh token. A refresh token would outlive the assertion and turn a
	// short-lived, revocable statement into a long-lived credential -- the exact
	// property workload identity exists to avoid. The client still holds the
	// means to get another assertion, which is cheaper and stays revocable at
	// the issuer.
	writeJSON(w, http.StatusOK, &tokenResponse{
		AccessToken: at,
		TokenType:   bearerOrDPoP(jkt),
		ExpiresIn:   int(tokens.DefaultAccessTokenTTL.Seconds()),
		Scope:       joinScopes(scopes),
	})
}

// assertionAudiences is every value an assertion may legitimately use to name
// this deployment.
//
// The issuer identifier, its registered aliases, AND the token endpoint URL.
//
// The last one is interoperability rather than laxity. RFC 7523 §3 item 3 asks
// for "a value that identifies the authorization server", and two conventions
// grew up around that: OpenID-shaped deployments use the issuer, while Google's
// service-account flow -- which is what most RFC 7523 client libraries were
// written against -- uses the token endpoint URL. Ory's implementation matches on
// the token endpoint only; matching on either means a client library written for
// either convention works here without the operator discovering the difference
// through a refusal that names no cause.
//
// Both values are this server's own identity, so accepting either does not widen
// what the audience check protects: an assertion addressed to somebody else still
// matches neither.
func (s *Server) assertionAudiences() []string {
	out := s.acceptedIssuers()
	for _, base := range s.acceptedIssuers() {
		out = append(out, strings.TrimSuffix(base, "/")+oidc.PathToken)
	}
	return out
}
