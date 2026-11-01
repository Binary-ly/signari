package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/extfactor"
	"signari.dev/engine/internal/flow"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The external_factor stage (10.03): the browser leaves for a service the
// operator registered and comes back with an answer that service signed.
// internal/extfactor is the contract; this is the two ends of the journey.
//
// The answer is tied to the browser by the pending cookie, which only this
// stage's callback may continue, and to the sign-in by a nonce spent once. It
// comes back by GET because a redirect is what every such service can do, and
// because the cookie is SameSite=Lax: a cross-site POST would arrive without it.

// factorStagePrefix starts a pending token only one factor's callback may
// continue. Every other page compares Stage whole, so none of them accepts it.
const factorStagePrefix = "external_factor:"

// factorCallbackPath is where a service sends the browser back.
const factorCallbackPath = "/login/external-factor/callback"

var (
	errExternalFactorNoAnswer = errors.New("it did not come back with exactly one response")
	errExternalFactorReplayed = errors.New("its nonce was already spent, has expired, or is another sign-in's")
)

// beginExternalFactor sends the browser to a registered service.
func (s *Server) beginExternalFactor(w http.ResponseWriter, r *http.Request,
	userID, orgID, name string, amr []string, authzQuery string) {

	ctx := r.Context()
	broken := func(what string, err error) {
		s.log.Error(what, "factor", name, "err", err, "correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: audit.EventLoginFailed, OrgID: orgID, SubjectID: userID, CorrelationID: correlationID(ctx),
			Detail: map[string]any{"reason": "external_factor_unavailable", "factor": name},
		})
		s.clearPending(w)
		s.federationError(w, r, "This sign-in cannot be completed. Please tell an administrator.")
	}

	// Gone since the flow was applied, which removing it refuses but a stored
	// document written by hand does not. Refused rather than passed: the file
	// says this person is asked.
	f, err := store.LoadExternalFactor(ctx, s.db, orgID, name)
	if err != nil {
		broken("reading the external factor a flow names", err)
		return
	}
	hint, err := store.FactorLoginHint(ctx, s.db, userID)
	if err != nil {
		broken("reading who an external factor asks about", err)
		return
	}
	target, err := url.Parse(f.URL)
	if err != nil {
		broken("reading an external factor's url", err)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		broken("generating an external factor's nonce", err)
		return
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
		broken("signing an external factor's challenge", err)
		return
	}
	now := time.Now()
	challenge, err := tokens.NewSigner(key).SignJSON(extfactor.Challenge{
		Issuer: s.cfg.Issuer, Audience: f.Issuer, Subject: userID, LoginHint: hint, Nonce: nonce,
		ReturnTo: s.cfg.Issuer + factorCallbackPath, IssuedAt: now.Unix(),
		Expiry: now.Add(extfactor.ChallengeLifetime).Unix(),
	}, extfactor.TypChallenge)
	if err != nil {
		broken("signing an external factor's challenge", err)
		return
	}
	if err := store.BeginFactorChallenge(ctx, s.db, orgID, name, userID, nonce, extfactor.ChallengeLifetime); err != nil {
		broken("recording an external factor's challenge", err)
		return
	}
	if err := s.setPendingCookieFor(w, userID, orgID, amr, authzQuery, factorStagePrefix+name); err != nil {
		broken("issuing the pending token for an external factor", err)
		return
	}
	q := target.Query()
	q.Set("challenge", challenge)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// handleExternalFactorCallback takes the service's answer.
func (s *Server) handleExternalFactorCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, err := s.readPending(r)
	if err != nil {
		s.federationError(w, r, "That sign-in has expired. Please start again.")
		return
	}
	name, ok := strings.CutPrefix(pending.Stage, factorStagePrefix)
	if !ok {
		s.federationError(w, r, "That sign-in has expired. Please start again.")
		return
	}
	refuse := func(why error) {
		s.log.Warn("an external factor's answer was refused", "factor", name, "err", why,
			"correlation_id", correlationID(ctx))
		s.auditDetached(ctx, audit.Event{
			Type: "mfa.external_factor_failed", OrgID: pending.OrgID, SubjectID: pending.Subject,
			CorrelationID: correlationID(ctx), Detail: map[string]any{"factor": name},
		})
		s.clearPending(w)
		s.federationError(w, r, "That sign-in could not be completed.")
	}

	// One answer. Two are refused rather than one chosen, because what was
	// verified and what was recorded must describe the same request.
	response := r.URL.Query()["response"]
	if len(response) != 1 {
		refuse(errExternalFactorNoAnswer)
		return
	}
	f, err := store.LoadExternalFactor(ctx, s.db, pending.OrgID, name)
	if err != nil {
		refuse(err)
		return
	}
	answer, err := extfactor.Verify(response[0], extfactor.Expected{
		Issuer: f.Issuer, Audience: s.cfg.Issuer, Subject: pending.Subject, JWKS: f.JWKS, Declared: f.AMR,
	}, time.Now())
	if err != nil {
		refuse(err)
		return
	}
	spent, err := store.SpendFactorChallenge(ctx, s.db, pending.OrgID, name, pending.Subject, answer.Nonce)
	if err != nil {
		s.log.Error("spending an external factor's nonce", "err", err, "correlation_id", correlationID(ctx))
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	if !spent {
		refuse(errExternalFactorReplayed)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.federationError(w, r, "Something went wrong. Please try again.")
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if aerr := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.external_factor_passed", OrgID: pending.OrgID, SubjectID: pending.Subject,
		CorrelationID: correlationID(ctx), Detail: map[string]any{"factor": name, "amr": answer.AMR},
	}); aerr != nil {
		s.log.Error("recording an external factor's answer", "err", aerr)
	}
	proved := flow.Mark(append(slices.Clone(pending.AMR), answer.AMR...), flow.StageExternalFactor, name)
	s.completeSignIn(w, r, tx, pending.Subject, pending.OrgID, proved, pending.Authz)
}
