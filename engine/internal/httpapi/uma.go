package httpapi

import (
	"errors"
	"io"
	"net/http"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/authzen"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// UMA 2.0, the protocol surface. See internal/uma for what it is and what is
// deliberately absent.
//
//	POST /uma2/permission    resource server authenticates -> ticket
//	POST /oauth2/token       grant_type=urn:...:uma-ticket -> RPT

// handleUMAPermission issues a permission ticket to a resource server.
//
// Federated Authorization §3.1. The caller is a registered, authenticated client
// acting as a resource server: the endpoint mints a credential that a stranger
// will present back here, so an open one would let anybody manufacture tickets
// describing any resource.
func (s *Server) handleUMAPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	c, ok := s.authenticateResourceServer(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeUMAError(w, uma.InvalidRequest("the request body could not be read"))
		return
	}
	perms, uerr := uma.ParsePermissions(body)
	if uerr != nil {
		writeUMAError(w, uerr)
		return
	}

	ticket, err := uma.NewTicket()
	if err != nil {
		s.log.Error("minting a permission ticket", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if _, err := store.CreatePermissionTicket(ctx, s.db, c.OrgID, c.ClientID,
		store.HashToken(ticket), perms, uma.TicketLifetime); err != nil {
		s.log.Error("recording a permission ticket", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	// §3.2: "HTTP 201 Created" with the ticket.
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": ticket})
}

// authenticateResourceServer admits only a confidential client.
//
// A resource server is not a browser and has no user in front of it, so there is
// no public-client case to accommodate. Refused explicitly rather than falling
// through to a secret comparison that an empty secret would pass.
func (s *Server) authenticateResourceServer(w http.ResponseWriter, r *http.Request) (*clients.Client, bool) {
	ctx := r.Context()
	// Credentials from the HEADER only, and no ParseForm call.
	//
	// The permission request's body is JSON (Federated Authorization §3.1), so
	// there are no form-encoded credentials to find and calling ParseForm would
	// consume the body this handler is about to read. An earlier version called
	// it and discarded the error, which the repository's own
	// TestNoParameterIsDiscardedSilently correctly refused: a discarded error is
	// shaped like a check and is not one.
	creds, cerr := oauth.ParseClientCredentials(r.Header, nil)
	if cerr != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", cerr.Description)
		return nil, false
	}
	c, err := s.lookupClient(ctx, creds.ClientID)
	if err != nil || c == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return nil, false
	}
	if c.Type != "confidential" {
		writeError(w, http.StatusUnauthorized, "invalid_client",
			"the permission endpoint requires a confidential client: it mints a "+
				"credential a stranger will present back here")
		return nil, false
	}
	if err := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); err != nil {
		s.log.Info("UMA permission endpoint client authentication failed",
			"client_id", creds.ClientID, "err", err, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return nil, false
	}
	return c, true
}

// handleUMAGrant is §3.3: ticket in, RPT out.
func (s *Server) handleUMAGrant(w http.ResponseWriter, r *http.Request, c *clients.Client) {
	ctx := r.Context()

	// Not implemented, and refused rather than ignored. A client that pushes
	// claims and receives a token concludes the claims were weighed.
	for _, unsupported := range []string{"claim_token", "pct", "rpt"} {
		if r.PostForm.Get(unsupported) != "" {
			writeUMAError(w, uma.InvalidRequest(unsupported+" is not supported by this "+
				"server; it answers from policy alone, so there is nothing for pushed "+
				"claims, a persisted claims token or an RPT upgrade to affect"))
			return
		}
	}

	ticket := r.PostForm.Get("ticket")
	if ticket == "" {
		writeUMAError(w, uma.InvalidRequest("ticket is required for the UMA grant"))
		return
	}

	// Redeemed BEFORE the decision. §3.3.1's MUST is that presentation
	// invalidates, not that a successful presentation invalidates -- so a refused
	// request spends the ticket too, and a client cannot grind the same ticket
	// against policy while claims change underneath it.
	t, err := store.RedeemPermissionTicket(ctx, s.db, store.HashToken(ticket))
	if errors.Is(err, store.ErrTicketUnknown) {
		writeUMAError(w, uma.InvalidGrant("this permission ticket is unknown, has "+
			"expired, or has already been presented; ask the resource server for a new one"))
		return
	}
	if err != nil {
		s.log.Error("redeeming a permission ticket", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	if t.OrgID != c.OrgID {
		// A ticket minted in one organisation, presented by a client in another.
		writeUMAError(w, uma.InvalidGrant("this permission ticket was not issued in "+
			"this organisation"))
		return
	}

	// Who is asking. The UMA grant is a client credential exchange unless the
	// client presents something identifying an end user, and we do not accept
	// pushed claims -- so the requesting party is the client itself.
	subject := c.ClientID

	// The decision comes from the SAME policy decision point that answers
	// /access/v1/evaluation. One question, one answer.
	for _, p := range t.Permissions {
		for _, scope := range p.ResourceScopes {
			resp, derr := s.decide(ctx, c.OrgID, authzen.Request{
				Subject:  authzen.Subject{Type: "client", ID: subject},
				Resource: authzen.Resource{Type: p.ResourceType, ID: p.ResourceID},
				Action:   authzen.Action{Name: scope},
			})
			if derr != nil {
				s.log.Error("evaluating a UMA permission", "err", derr)
				writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
				return
			}
			if !resp.Decision {
				s.auditDetached(ctx, audit.Event{
					Type: "uma.denied", OrgID: c.OrgID,
					CorrelationID: correlationID(ctx),
					Detail: map[string]any{
						"client_id": c.ClientID, "resource_type": p.ResourceType,
						"resource_id": p.ResourceID, "scope": scope,
					},
				})
				// §3.3.6: request_denied, 403. Final -- the client should not retry
				// with the same request, which is what distinguishes it from
				// invalid_grant.
				writeUMAError(w, uma.Denied("this client may not "+scope+" "+
					p.ResourceType+":"+p.ResourceID))
				return
			}
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
		s.log.Error("no signing key for an RPT", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	now := time.Now()
	jti, err := newSID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}
	scopes := uma.Scopes(t.Permissions)
	rpt, err := tokens.NewSigner(key).SignJSON(tokens.AccessTokenClaims{
		Issuer:   s.cfg.Issuer,
		Subject:  subject,
		Audience: []string{t.ResourceServer},
		Expiry:   now.Add(tokens.DefaultAccessTokenTTL).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		ClientID: c.ClientID,
		Scope:    joinScopes(scopes),
	}, tokens.TypAccessToken)
	if err != nil {
		s.log.Error("signing an RPT", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	s.auditDetached(ctx, audit.Event{
		Type: "uma.granted", OrgID: c.OrgID, CorrelationID: correlationID(ctx),
		Detail: map[string]any{
			"client_id": c.ClientID, "resource_server": t.ResourceServer,
			"scope": joinScopes(scopes),
		},
	})

	// §3.3.5: the RFC 6749 §5.1 response shape, token_type Bearer.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": rpt,
		"token_type":   "Bearer",
		"expires_in":   int(tokens.DefaultAccessTokenTTL.Seconds()),
		"scope":        joinScopes(scopes),
	})
}

// writeUMAError renders §3.3.6's error with its own status.
func writeUMAError(w http.ResponseWriter, e *uma.Error) {
	status := e.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]any{"error": e.Code, "error_description": e.Description}
	if e.Ticket != "" {
		body["ticket"] = e.Ticket
	}
	writeJSON(w, status, body)
}
