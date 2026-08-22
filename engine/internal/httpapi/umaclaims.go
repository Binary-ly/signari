package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// The UMA 2.0 claims interaction endpoint, §3.3.2 and §3.3.3.
//
//	GET  /uma2/claims?client_id=&ticket=&claims_redirect_uri=&state=
//	POST /uma2/claims   (the confirmation, carrying only a handle and a CSRF token)
//
// # Why this is two requests
//
// §5.1 is unusually specific about what protection means here:
//
//	"The authorization server MUST implement CSRF protection for its claims
//	interaction endpoint and ensure that a malicious client cannot obtain
//	authorization without the awareness and involvement of the requesting party."
//
// Read the second half. A token alone does not satisfy it. If the GET redeemed
// the ticket and redirected, then an `<img src="https://as.example/uma2/claims?
// client_id=...&ticket=...">` in an email spends the victim's identity with no
// awareness and no involvement whatsoever -- the browser does it while the page
// is loading, and the victim's only evidence is a broken image.
//
// So the GET renders what is being asked and the POST acts on it. That is the
// "awareness and involvement" half; the CSRF token is the other half, and
// neither substitutes for the other.
//
// # What happens between the redirects is deliberately not a protocol
//
// §3.3.3: "Interactive claims-gathering processes are outside the scope of this
// specification. The purpose of the interaction is for the authorization server
// to gather information for its own authorization assessment purposes. This
// redirection does not involve sending any of the information back to the
// client."
//
// The claim gathered here is identity: who the requesting party is. Nothing
// about that person is sent to the client -- the client receives a ticket, and
// what the ticket now means is entirely ours.

// InteractionLifetime bounds a confirmation page.
//
// Longer than a permission ticket, because a person is reading it. Shorter than
// a sign-in, because the ticket it refers to expires anyway and an interaction
// outliving its own ticket is a page whose button cannot work.
const InteractionLifetime = 10 * time.Minute

// claimsInteractionPath is where §3.3.2 sends a requesting party.
const claimsInteractionPath = "/uma2/claims"

// handleUMAClaims serves both halves of the interaction.
func (s *Server) handleUMAClaims(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.finishUMAClaims(w, r)
		return
	}
	s.beginUMAClaims(w, r)
}

// beginUMAClaims validates the redirect, authenticates the person, and shows
// them what is being asked.
func (s *Server) beginUMAClaims(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	clientID, ticket := q.Get("client_id"), q.Get("ticket")

	if clientID == "" || ticket == "" {
		// §3.3.3: a missing or invalid client identifier is one of the two faults
		// the requesting party must be TOLD about rather than redirected for --
		// "the authorization server SHOULD inform the requesting party of the
		// error and MUST NOT automatically redirect the user agent".
		s.renderClaimsError(w, r, "This request is incomplete.",
			"It must carry both a client_id and a ticket. Nothing has been changed.")
		return
	}
	c, err := s.lookupClient(ctx, clientID)
	if err != nil || c == nil || !c.Enabled {
		s.renderClaimsError(w, r, "That application is not registered here.",
			"Nothing has been changed. If you followed a link from an application, "+
				"it may be misconfigured.")
		return
	}

	redirectURI, ok := claimsRedirectFor(c, q.Get("claims_redirect_uri"))
	if !ok {
		// The second fault §3.3.3 forbids redirecting for. Redirecting to an
		// unregistered URI here is the open redirect §5.1 names, and it is worse
		// than the usual kind: the thing being handed to the attacker's URL is a
		// permission ticket bound to the person who just signed in.
		s.renderClaimsError(w, r, "That application cannot receive you back.",
			"Its claims redirection URI is missing, or does not exactly match one "+
				"it registered. You have not been sent anywhere.")
		return
	}

	// The ticket is READ, not redeemed. §3.3.1 spends a ticket when the client
	// "presents" it here -- and the presentation that counts is the one the
	// person acts on. Spending it now would mean a page reload, or a browser
	// prefetching the link, destroys the request before anybody decided.
	t, err := store.InspectPermissionTicket(ctx, s.db, store.HashToken(ticket))
	if errors.Is(err, store.ErrTicketUnknown) {
		s.renderClaimsError(w, r, "This request has expired.",
			"Permission tickets are short-lived and single-use. Return to the "+
				"application and try again.")
		return
	}
	if err != nil {
		s.log.Error("reading a permission ticket for claims gathering", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}
	if t.OrgID != c.OrgID {
		s.renderClaimsError(w, r, "This request does not belong here.",
			"The ticket was issued in a different organisation.")
		return
	}

	// Now, and only now, the person. Parked AFTER the validation above so that a
	// malformed or hostile link does not first send somebody to a sign-in form:
	// a person who signs in and is then told the request was invalid has typed
	// their password for an attacker's benefit.
	_, userID, orgID, signedIn := s.currentSession(r)
	if !signedIn {
		http.Redirect(w, r, parkLogin(claimsInteractionPath+"?"+r.URL.RawQuery),
			http.StatusSeeOther)
		return
	}
	if orgID != c.OrgID {
		s.renderClaimsError(w, r, "You are signed in elsewhere.",
			"This request belongs to a different organisation than your session.")
		return
	}

	handle, err := newSID()
	if err != nil {
		s.log.Error("minting a claims interaction handle", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}
	state, hasState := q["state"]
	i := store.Interaction{
		OrgID: c.OrgID, ClientID: c.ClientID,
		TicketHash: store.HashToken(ticket), ClaimsRedirectURI: redirectURI,
		RequestingParty: userID, HasState: hasState,
	}
	if hasState && len(state) > 0 {
		i.State = state[0]
	}
	if _, err := store.BeginInteraction(ctx, s.db, i, store.HashToken(handle),
		InteractionLifetime); err != nil {
		s.log.Error("recording a claims interaction", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}

	// What is being asked, in the person's own terms. The resource server named
	// resources and scopes; both are shown, because "share your data" tells
	// somebody nothing and is the reason consent screens are ignored.
	type ask struct{ Resource, Scopes string }
	asks := make([]ask, 0, len(t.Permissions))
	for _, p := range t.Permissions {
		asks = append(asks, ask{
			Resource: p.ResourceType + " " + p.ResourceID,
			Scopes:   strings.Join(p.ResourceScopes, ", "),
		})
	}
	s.renderPage(w, r, "umaclaims", map[string]any{
		"ClientName":     c.DisplayName,
		"ResourceServer": t.ResourceServer,
		"Asks":           asks,
		"Handle":         handle,
		"CSRF":           csrf,
		"CSRFField":      csrfFormField,
	})
}

// finishUMAClaims acts on the confirmation.
func (s *Server) finishUMAClaims(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.renderClaimsError(w, r, "That form did not arrive intact.", "Please try again.")
		return
	}
	// CSRF BEFORE anything else that touches state, and before the session
	// lookup, so a forged post cannot spend an interaction even if it somehow
	// carried a session cookie.
	if !checkCSRF(r) {
		s.log.Info("uma claims interaction refused: csrf",
			"correlation_id", correlationID(ctx))
		s.renderClaimsError(w, r, "That request could not be verified.",
			"Return to the application and start again.")
		return
	}
	_, userID, _, signedIn := s.currentSession(r)
	if !signedIn {
		s.renderClaimsError(w, r, "Your session has ended.",
			"Sign in and start again from the application.")
		return
	}

	handle := r.PostForm.Get("handle")
	if handle == "" {
		s.renderClaimsError(w, r, "That form is incomplete.", "Please try again.")
		return
	}
	// The interaction row is the ONLY source of the ticket and the redirect URI.
	// Both were validated when the page was drawn and neither is re-read from
	// the form, so a submission cannot carry values the person was never shown.
	i, err := store.ConsumeInteraction(ctx, s.db, store.HashToken(handle), userID)
	if errors.Is(err, store.ErrInteractionUnknown) {
		s.renderClaimsError(w, r, "This confirmation is no longer valid.",
			"It may have expired, or already been used. Start again from the "+
				"application.")
		return
	}
	if err != nil {
		s.log.Error("consuming a claims interaction", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}

	// NOW the ticket is spent, per §3.3.1: "The authorization server MUST
	// invalidate a permission ticket when the client presents the permission
	// ticket to either the token endpoint or the claims interaction endpoint."
	t, err := store.RedeemPermissionTicket(ctx, s.db, i.TicketHash)
	if errors.Is(err, store.ErrTicketUnknown) {
		s.renderClaimsError(w, r, "This request has expired.",
			"Return to the application and try again.")
		return
	}
	if err != nil {
		s.log.Error("redeeming a permission ticket at the claims endpoint", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}

	// §3.3.3: "A permission ticket that allows the client to make further
	// requests... The value MUST NOT be the same as the one the client used to
	// make its request." A fresh random value, so that is structural rather than
	// a comparison somebody has to remember to make.
	next, err := uma.NewTicket()
	if err != nil {
		s.log.Error("minting a successor permission ticket", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}
	if err := store.MintSuccessorTicket(ctx, s.db, store.HashToken(next),
		store.TicketOrigin{
			OrgID: t.OrgID, ResourceServer: t.ResourceServer,
			Permissions:     t.Permissions,
			RequestingParty: userID,
			// Bound to the client that brought the person here. The identity was
			// proved to THIS client; a second client presenting the successor
			// ticket would be handed somebody else's proof.
			BoundClient: i.ClientID,
		}, uma.TicketLifetime); err != nil {
		s.log.Error("recording a successor permission ticket", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "uma.claims_gathered", OrgID: t.OrgID, SubjectID: userID,
		ClientID: i.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"resource_server": t.ResourceServer,
			"scope":           joinScopes(uma.Scopes(t.Permissions)),
		},
	})

	// §3.3.3's redirect. The query component of a registered URI "MUST be
	// retained when adding additional parameters", so parameters are appended to
	// whatever the client registered rather than replacing it.
	target, err := appendQuery(i.ClaimsRedirectURI, func(v url.Values) {
		v.Set("ticket", next)
		// "The same state value that the client provided in the request. It MUST
		// be present if and only if the client provided it." A client that sent no
		// state and receives one back cannot match it to anything, and a client
		// that sent an EMPTY state must get an empty one back -- which is why the
		// interaction records whether there was a state at all, not just its value.
		if i.HasState {
			v.Set("state", i.State)
		}
	})
	if err != nil {
		s.log.Error("building the claims redirect", "err", err)
		s.renderClaimsError(w, r, "Something went wrong.", "Please try again.")
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// claimsRedirectFor resolves §3.3.2's claims_redirect_uri parameter.
//
//	"REQUIRED if the client has pre-registered multiple claims redirection URIs
//	or has pre-registered no claims redirection URI; OPTIONAL only if the client
//	has pre-registered a single claims redirection URI."
//
// followed by:
//
//	"The client SHOULD pre-register its claims_redirect_uri with the
//	authorization server, and the authorization server SHOULD require all
//	clients, and MUST require public clients, to pre-register their claims
//	redirection endpoints."
//
// This server takes the SHOULD: every client must pre-register, confidential
// ones included. The specification's "REQUIRED if the client has pre-registered
// no claims redirection URI" describes a server that will accept an
// unregistered URI, and that server has an open redirect whose payload is a
// permission ticket bound to whoever just signed in. There is no configuration
// to relax this.
// A client with nothing registered is refused by both branches below -- an
// empty list has no single element to default to, and HasClaimsRedirectURI
// finds nothing in it. There WAS an explicit `len == 0` guard here saying so;
// it is gone because no mutation of it changed any behaviour, which by this
// repository's own rule makes it something shaped like a check that is not one.
// The policy it stated lives in the doc comment above, where it cannot rot into
// looking like enforcement.
func claimsRedirectFor(c *clients.Client, candidate string) (string, bool) {
	if candidate == "" {
		// The one case where omitting it is allowed, and only that case.
		if len(c.ClaimsRedirectURIs) == 1 {
			return c.ClaimsRedirectURIs[0], true
		}
		return "", false
	}
	if !c.HasClaimsRedirectURI(candidate) {
		return "", false
	}
	return candidate, true
}

// appendQuery adds parameters to a URI, keeping any it already carries.
func appendQuery(raw string, add func(url.Values)) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	v := u.Query()
	add(v)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// renderClaimsError tells the requesting party what went wrong, here, on this
// origin -- never by redirecting.
func (s *Server) renderClaimsError(w http.ResponseWriter, r *http.Request, title, detail string) {
	w.WriteHeader(http.StatusBadRequest)
	s.renderPage(w, r, "umaclaimserr", map[string]any{
		"Title": title, "Detail": detail,
	})
}

// --- the requesting party ---------------------------------------------------

// requestingParty is who a UMA grant is being asked on behalf of.
//
// The zero value means the client itself, which is where every flow starts and
// is what this server did for everybody before claims gathering existed.
type requestingParty struct {
	userID string
	// ref is how the authorization model refers to this person: their email when
	// they have one, their user id otherwise. See store.RequestingPartyRef for
	// why the two are not interchangeable.
	ref string
}

// requestingParty establishes who is asking, §3.3.1 and §3.3.2.
//
// Two sources, and they must agree:
//
//   - the ticket, when a previous trip through the claims interaction endpoint
//     bound an identity to it;
//   - `claim_token`, pushed directly by the client.
//
// A client that has already gathered claims interactively AND pushes a token is
// asserting two identities for one request. That is refused rather than resolved
// by precedence: whichever one a server picked, the other party's identity would
// have been presented and quietly discarded, and a resource owner reading the
// audit trail would see only the winner.
func (s *Server) requestingParty(ctx context.Context, r *http.Request,
	c *clients.Client, t *store.Ticket) (requestingParty, *uma.Error) {

	pushed := r.PostForm.Get("claim_token")
	format := r.PostForm.Get("claim_token_format")

	// §3.3.1: "If this parameter is used, it MUST appear together with the
	// claim_token_format parameter", and the converse. Enforced both ways: a
	// format with no token is a client that thinks it pushed something.
	if (pushed == "") != (format == "") {
		return requestingParty{}, uma.InvalidRequest(
			"claim_token and claim_token_format must appear together (section 3.3.1)")
	}

	if t.RequestingParty != "" {
		if pushed != "" {
			return requestingParty{}, uma.InvalidRequest(
				"this permission ticket already identifies a requesting party from " +
					"interactive claims gathering, and this request also pushes a " +
					"claim_token; the two would have to be the same person and this " +
					"server will not guess which one you meant")
		}
		ref, err := store.RequestingPartyRef(ctx, s.db, t.RequestingParty)
		if err != nil {
			if !errors.Is(err, store.ErrNoSuchSubject) {
				s.log.Error("resolving a bound requesting party", "err", err)
			}
			return requestingParty{}, uma.InvalidGrant(
				"the requesting party on this ticket no longer exists")
		}
		return requestingParty{userID: t.RequestingParty, ref: ref}, nil
	}

	if pushed == "" {
		return requestingParty{}, nil
	}
	if format != uma.ClaimTokenFormatIDToken {
		// Named, not generic. A client that sent a SAML assertion needs to know
		// which format would have worked, and §3.3.1 says the server "SHOULD
		// document the profiles it supports in its discovery document" -- so the
		// answer exists and withholding it here helps nobody.
		return requestingParty{}, s.claimTokenNeedInfo(ctx, t,
			"claim_token_format "+format+" is not supported; this server accepts "+
				uma.ClaimTokenFormatIDToken+", an ID token it issued itself")
	}
	raw, derr := uma.DecodeClaimToken(pushed)
	if derr != nil {
		return requestingParty{}, s.claimTokenNeedInfo(ctx, t, derr.Error())
	}

	// Verified as an ID TOKEN, against our own key set and our own issuer.
	//
	// # Why only our own
	//
	// §3.3.1: "The client and authorization server together might need to
	// establish proper audience restrictions for the claim token prior to claims
	// pushing." There is no protocol here for establishing that with a third
	// party, so accepting an assertion from an arbitrary issuer would mean
	// accepting whoever the client chose to believe -- and the client is the one
	// asking for access.
	//
	// An ID token this server issued to this very client is a claim we already
	// stand behind, and the audience check below is the restriction §3.3.1 asks
	// for, made concrete.
	aud, err := tokens.VerifyIDTokenAudience(s.cfg.Keys, s.cfg.Issuer, raw)
	if err != nil {
		return requestingParty{}, uma.InvalidGrant(
			"the pushed claim_token is not an ID token issued by this server")
	}
	if aud != c.ClientID {
		// The audience restriction, enforced. Without it a client could push an ID
		// token it obtained by any means -- from a log, from a referrer header,
		// from another application it also operates -- and be treated as acting
		// for that person.
		return requestingParty{}, uma.InvalidGrant(
			"the pushed claim_token was issued to a different client")
	}

	var claims tokens.IDTokenClaims
	if err := tokens.VerifyTypedJSON(s.cfg.Keys, []string{s.cfg.Issuer}, raw,
		tokens.TypIDToken, &claims); err != nil {
		return requestingParty{}, uma.InvalidGrant("the pushed claim_token is not readable")
	}
	// Expiry, which VerifyIDTokenAudience deliberately does not enforce -- it
	// exists for `id_token_hint` at logout, where an expired token is the normal
	// case. Here it is not: an expired ID token proves the person authenticated
	// once, at some point, and this grant is about who is asking NOW.
	if claims.Expiry == 0 || time.Now().After(time.Unix(claims.Expiry, 0)) {
		return requestingParty{}, s.claimTokenNeedInfo(ctx, t,
			"the pushed claim_token has expired; fetch a fresh ID token")
	}
	ref, err := store.RequestingPartyRef(ctx, s.db, claims.Subject)
	if err != nil {
		return requestingParty{}, uma.InvalidGrant(
			"the pushed claim_token names a subject this server does not know")
	}
	return requestingParty{userID: claims.Subject, ref: ref}, nil
}

// claimTokenNeedInfo answers a RECOVERABLE claim-token fault.
//
// §3.3.6's own definition of need_info: "The authorization server needs
// additional information in order for a request to succeed, for example, a
// provided claim token was invalid or expired, or had an incorrect format".
//
// So an expired or wrongly-formatted claim token is not `invalid_grant` -- which
// would tell the client its TICKET was bad, when the ticket was fine -- it is a
// request for a better token, with a fresh ticket to present it on and
// `required_claims` naming what would work.
//
// # What deliberately does NOT come here
//
// A token whose signature does not verify, or whose audience is another client.
// Those are not "we need more information": they are a client presenting a
// credential it should not have, and answering with an invitation to retry
// dresses that up as a recoverable mistake. Those stay invalid_grant.
//
// A failure to mint the successor degrades to invalid_grant rather than a 500.
// need_info without a ticket is malformed -- §3.3.6 makes it REQUIRED -- and a
// malformed 403 is worse for the client than a well-formed 400.
func (s *Server) claimTokenNeedInfo(ctx context.Context, t *store.Ticket, why string) *uma.Error {
	next, err := s.successorTicket(ctx, t, "", "", "")
	if err != nil {
		s.log.Error("minting a need_info ticket for a claim token fault", "err", err)
		return uma.InvalidGrant(why)
	}
	return uma.NeedInfo(next, strings.TrimRight(s.cfg.Issuer, "/")+claimsInteractionPath,
		[]uma.RequiredClaim{uma.SubjectClaim(s.cfg.Issuer)}, why)
}

// refuseUMA chooses between §3.3.6's three refusals.
//
// §3.3.4 leaves the choice to the implementation -- "The choice of error depends
// on policy conditions and the authorization server's implementation choices" --
// and notes that need_info, request_denied and request_submitted "are dependent
// on authorization assessment". The rule here is:
//
//   - nobody identified, and this client CAN identify somebody: `need_info`.
//     Gathering claims could change the answer, so a final refusal would be wrong.
//   - nobody identified, and it cannot: `request_denied`. See below.
//   - somebody identified, and this deployment records requests for a resource
//     owner: `request_submitted`. A human can still say yes.
//   - somebody identified, and it does not: `request_denied`. FINAL, and
//     honestly so -- asking the same question again cannot produce a different
//     answer, and telling a client to poll for a decision nobody will be asked
//     to make is worse than refusing.
//
// # Why "can identify somebody" is a per-client fact
//
// The obvious rule -- unidentified always means need_info -- is wrong for the
// machine-to-machine deployments this grant served before claims gathering
// existed, where policy is written about CLIENTS and the client genuinely is
// the requesting party. Sending one of those a `redirect_user` hint invites it
// to redirect a user that does not exist, and §3.3.6 says so itself: "If the
// requesting party is not an end-user, then no client action is possible on
// receiving the hint."
//
// Registered claims redirection URIs are the deployment saying, per client,
// "this one acts for people". That is an explicit switch an operator sets with
// `signari client set-claims-redirects`, not a guess -- and every client that
// existed before this feature keeps the answer it used to get.
func (s *Server) refuseUMA(w http.ResponseWriter, r *http.Request, c *clients.Client,
	t *store.Ticket, party requestingParty, p uma.Permission, scope string) {

	ctx := r.Context()
	what := scope + " " + p.ResourceType + ":" + p.ResourceID

	if party.userID == "" {
		if len(c.ClaimsRedirectURIs) == 0 {
			writeUMAError(w, uma.Denied("this client may not "+what))
			return
		}
		next, err := s.successorTicket(ctx, t, "", "", "")
		if err != nil {
			s.log.Error("minting a need_info ticket", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
			return
		}
		writeUMAError(w, uma.NeedInfo(next,
			strings.TrimRight(s.cfg.Issuer, "/")+claimsInteractionPath,
			[]uma.RequiredClaim{uma.SubjectClaim(s.cfg.Issuer)},
			"this server does not know who is asking, and policy on "+what+
				" is written about people; send the requesting party to the claims "+
				"interaction endpoint, or push an ID token"))
		return
	}

	settings, err := store.LoadUMASettings(ctx, s.db, c.OrgID)
	if err != nil {
		s.log.Error("reading UMA settings", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if !settings.OwnerIntervention {
		writeUMAError(w, uma.Denied("the requesting party may not "+what))
		return
	}

	pending, err := store.SubmitRequest(ctx, s.db, store.PendingRequest{
		OrgID: c.OrgID, ResourceServer: t.ResourceServer, ClientID: c.ClientID,
		RequestingParty: party.userID, Permissions: t.Permissions,
	}, PendingRequestLifetime)
	if err != nil {
		s.log.Error("submitting a UMA request for owner intervention", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	next, err := s.successorTicket(ctx, t, party.userID, c.ClientID, pending.ID)
	if err != nil {
		s.log.Error("minting a request_submitted ticket", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	s.auditDetached(ctx, audit.Event{
		Type: "uma.submitted", OrgID: c.OrgID, SubjectID: party.userID,
		ClientID: c.ClientID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{"resource_server": t.ResourceServer, "scope": what},
	})
	writeUMAError(w, uma.Submitted(next, int(settings.PollInterval.Seconds()),
		"a resource owner has been asked to decide whether the requesting party "+
			"may "+what))
}

// PendingRequestLifetime bounds how long an unanswered request stands.
//
// Seven days. A pending request is a standing offer to grant access; one nobody
// decided in a week should lapse rather than sit there to be approved later by
// somebody who no longer remembers what it was for.
const PendingRequestLifetime = 7 * 24 * time.Hour

// successorTicket mints the replacement §3.3.6 requires with need_info and
// request_submitted.
//
// The permissions are copied from the predecessor verbatim. Re-deriving them
// would let what is being asked for change between a refusal and the retry it
// invites, so a client told "you need X" could return and receive Y.
func (s *Server) successorTicket(ctx context.Context, t *store.Ticket,
	party, boundClient, pending string) (string, error) {

	next, err := uma.NewTicket()
	if err != nil {
		return "", err
	}
	if err := store.MintSuccessorTicket(ctx, s.db, store.HashToken(next),
		store.TicketOrigin{
			OrgID: t.OrgID, ResourceServer: t.ResourceServer,
			Permissions: t.Permissions, RequestingParty: party,
			BoundClient: boundClient, PendingRequest: pending,
		}, uma.TicketLifetime); err != nil {
		return "", err
	}
	return next, nil
}

// handleUMAMetadata serves §2's discovery document.
//
// "The structure of the discovery document MUST conform to that defined in
// [OAuthMeta]" -- so it is the RFC 8414 document, with UMA's own additions. It
// is built from the SAME builder that answers /.well-known/openid-configuration
// rather than restating the server: two documents describing one server
// eventually disagree, and the one a UMA client reads is the one nobody checks.
func (s *Server) handleUMAMetadata(w http.ResponseWriter, r *http.Request) {
	doc, err := oidc.Build(s.cfg)
	if err != nil {
		s.log.Error("building the UMA discovery document", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		s.log.Error("marshalling the UMA discovery document", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		s.log.Error("rebuilding the UMA discovery document", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	base := strings.TrimRight(s.cfg.Issuer, "/")
	// §2's static claims interaction endpoint. §3.3.2: "this process assumes
	// that the authorization server has statically declared its claims
	// interaction endpoint in its discovery document" -- so a client that wants
	// to redirect a requesting party BEFORE being told to, which is the whole
	// point of the static value, finds it here.
	out["claims_interaction_endpoint"] = base + claimsInteractionPath
	// §3.3.1: "This specification provides a means to define profiles of claim
	// token formats for use with UMA. The authorization server SHOULD document
	// the profiles it supports in its discovery document." One, and it is the
	// only one this server will act on.
	out["uma_profiles_supported"] = []string{uma.ClaimTokenFormatIDToken}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
}
