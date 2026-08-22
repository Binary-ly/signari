package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/store"
)

// Dynamic client registration, RFC 7591, with RFC 7592 management.
//
//	POST   /oauth2/register                 register
//	GET    /oauth2/register/{client_id}     read it back
//	DELETE /oauth2/register/{client_id}     remove it
//
// Off unless an organisation turns it on. See migration 0041 for why: an open
// registration endpoint is unbounded row creation by strangers, and a consent
// screen reading "Microsoft 365 wants access" is convincing whoever supplied
// that name.

// registrationRequest is the subset of RFC 7591 metadata acted on.
//
// Only fields we honour are modelled. An unmodelled field cannot be silently
// accepted and then ignored, which is how a client ends up believing it
// registered something it did not.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	LogoutURI               string   `json:"backchannel_logout_uri"`

	// CIBA §4 makes this REQUIRED client metadata for a client registering to
	// use CIBA, and this server implements poll mode only.
	//
	// Read so that a mismatch is refused rather than dropped. RFC 7591 §2 permits
	// ignoring unrecognised metadata, and ignoring THIS one has a specific
	// consequence: a client registering for `push` would be recorded as an
	// ordinary CIBA client, receive an `auth_req_id`, and wait for a delivery
	// that never comes. The same reasoning the backchannel endpoint already
	// applies to `client_notification_token` — "a client that receives an
	// auth_req_id concludes the mode it asked for was accepted, and would wait
	// forever" — belongs at registration too, where the client is still able to
	// act on being told.
	BackchannelTokenDeliveryMode string `json:"backchannel_token_delivery_mode"`

	// RFC 9449 §5.2 calls this client registration metadata, so this is where it
	// belongs: "A boolean value specifying whether the client always uses DPoP
	// for token requests ... If the value is true, the authorization server MUST
	// reject token requests from the client that do not contain the DPoP
	// header."
	//
	// Honoured from open registration because a client can only set it on itself,
	// and the only effect is that its own unproofed requests are refused. It
	// fails closed for the party that asked for it and touches nobody else.
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	// Rate limited whether or not it is open: this endpoint writes rows.
	//
	// Its OWN bucket. This shared the device flow's limiter, which meant the two
	// endpoints could not be tuned apart -- and when the device limit was
	// widened to stop one address locking out every television in the
	// deployment, dynamic registration would have silently been widened with
	// it. Sharing a limiter couples two unrelated decisions and the coupling is
	// invisible at both call sites.
	if !s.register.Allow() {
		writeError(w, http.StatusTooManyRequests, "temporarily_unavailable",
			"too many registrations just now")
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata",
			"the request body is not valid JSON")
		return
	}

	// Which organisation, and may this caller register at all?
	orgID, tokenID, err := s.authorizeRegistration(ctx, r)
	if err != nil {
		s.log.Info("registration refused", "err", err,
			"correlation_id", correlationID(ctx))
		// One answer for "not enabled here", "no token" and "bad token". Telling
		// a caller which would let them map where registration is open.
		writeError(w, http.StatusUnauthorized, "invalid_token",
			"registration is not available with these credentials")
		return
	}

	// CIBA §4: poll mode only, and discovery says so. A client asking for a mode
	// we do not implement is told now, while it can still act on being told.
	//
	// After authorisation deliberately: metadata feedback to a caller who may not
	// register here would let them probe what this issuer validates.
	if m := req.BackchannelTokenDeliveryMode; m != "" && m != "poll" {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata",
			"backchannel_token_delivery_mode "+m+" is not supported by this issuer; "+
				"backchannel_token_delivery_modes_supported lists poll, and a client "+
				"registered for ping or push would wait for a delivery that never comes")
		return
	}

	pol, err := store.LoadRegistrationPolicy(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("loading the registration policy", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Ceiling before validation: refusing early costs the caller nothing and
	// stops a flood doing work.
	count, err := store.CountDynamicClients(ctx, s.db, orgID)
	if err != nil {
		s.log.Error("counting dynamic clients", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if count >= pol.MaxClients {
		// Refuse, never evict. Deleting somebody's working client to make room
		// for a stranger's is worse than refusing the stranger.
		writeError(w, http.StatusForbidden, "invalid_client_metadata",
			fmt.Sprintf("this organisation has reached its limit of %d dynamically "+
				"registered clients", pol.MaxClients))
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uris is required: a client with none can never complete a flow")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validateRegisteredRedirect(u); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	// Scopes are intersected with what the policy allows rather than refused, so
	// a client asking for more gets what it may have and can see the difference
	// in the response -- which RFC 7591 §3.2.1 explicitly permits and which is
	// kinder than a rejection naming a scope catalogue the caller cannot read.
	granted := intersectScopes(strings.Fields(req.Scope), pol.AllowedScopes)
	if len(granted) == 0 {
		granted = []string{"openid"}
	}

	confidential := req.TokenEndpointAuthMethod != "none"
	if confidential && !pol.AllowConfidential {
		// A secret handed to a caller who appeared thirty seconds ago and cannot
		// be identified is a formality, not a credential.
		confidential = false
	}

	reg, err := store.RegisterClient(ctx, s.db, store.NewClientRegistration{
		OrgID:        orgID,
		DisplayName:  displayNameFor(req.ClientName),
		RedirectURIs: req.RedirectURIs,
		Scopes:       granted,
		Confidential: confidential,
		LogoutURI:    strings.TrimSpace(req.LogoutURI),
		TokenID:      tokenID,
		DPoPBound:    req.DPoPBoundAccessTokens,
	})
	if err != nil {
		s.log.Error("registering a client", "err", err, "org_id", orgID)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	s.log.Info("client registered dynamically", "client_id", reg.ClientID,
		"org_id", orgID, "confidential", confidential,
		"correlation_id", correlationID(ctx))

	body := map[string]any{
		"client_id":                  reg.ClientID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              req.RedirectURIs,
		"client_name":                reg.DisplayName,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      strings.Join(granted, " "),
		"token_endpoint_auth_method": "none",
		// RFC 7592: how the registrant manages this client afterwards. Shown
		// once, like every other credential here.
		"registration_access_token": reg.RegistrationToken,
		"registration_client_uri":   s.cfg.Issuer + "/oauth2/register/" + reg.ClientID,
		// RFC 7591 §3.2.1: "The authorization server MUST return all registered
		// metadata about this client." Echoed even when false, because the whole
		// value of the field is the client being able to confirm that the server
		// agreed to enforce it -- a client that asked to be pinned and was
		// silently not would believe it was constrained when it was not.
		"dpop_bound_access_tokens": req.DPoPBoundAccessTokens,
	}
	if confidential {
		body["client_secret"] = reg.ClientSecret
		body["token_endpoint_auth_method"] = "client_secret_basic"
		// No client_secret_expires_at: ours do not expire on a timer, and
		// claiming 0 (never) is at least honest rather than aspirational.
		body["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, body)
}

// handleRegisteredClient serves RFC 7592 read and delete.
func (s *Server) handleRegisteredClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	clientID := r.PathValue("clientID")
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token",
			"a registration access token is required")
		return
	}

	c, err := store.LoadRegisteredClient(ctx, s.db, clientID, sha256Sum(token))
	if err != nil {
		// Wrong token, wrong client, or a client that was never dynamically
		// registered: one answer, so this cannot be used to discover which
		// client ids exist.
		writeError(w, http.StatusUnauthorized, "invalid_token",
			"that token does not manage this client")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"client_id":     c.ClientID,
			"client_name":   c.DisplayName,
			"redirect_uris": c.RedirectURIs,
			"scope":         strings.Join(c.Scopes, " "),
			"grant_types":   []string{"authorization_code", "refresh_token"},
		})
	case http.MethodDelete:
		if err := store.DeleteRegisteredClient(ctx, s.db, clientID); err != nil {
			s.log.Error("deleting a registered client", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		s.log.Info("registered client deleted", "client_id", clientID,
			"correlation_id", correlationID(ctx))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "")
	}
}

// authorizeRegistration decides whether this caller may register, and where.
func (s *Server) authorizeRegistration(ctx context.Context, r *http.Request) (orgID, tokenID string, err error) {
	if token := bearerToken(r); token != "" {
		return store.RedeemRegistrationToken(ctx, s.db, sha256Sum(token))
	}

	// No token. Only an organisation that has explicitly opened registration
	// accepts this, and only when exactly one has -- "open" plus several
	// organisations has no answer to which one a stranger meant, and guessing
	// would put a client in the wrong tenant.
	org, err := store.SingleOpenRegistrationOrg(ctx, s.db)
	if err != nil {
		return "", "", err
	}
	return org, "", nil
}

// validateRegisteredRedirect applies the same rules an operator-registered
// client gets. A self-registered client is not held to a lower standard.
//
// That claim used to be false. This function had its own copy of the rules and
// was STRICTER than clients.ValidateRedirectURI, which the CLI and admin API use
// -- so `javascript:`, `data:` and `file:` were refused here and accepted there.
// The scheme allow-list now lives in clients.ValidateRedirectURI and both paths
// go through it; what remains below is the two rules dynamic registration adds.
func validateRegisteredRedirect(u string) error {
	if err := clients.ValidateRedirectURI(u); err != nil {
		return err
	}
	if strings.Contains(u, "*") {
		return fmt.Errorf("redirect_uri %q contains a wildcard; they are matched "+
			"exactly, because anything looser lets a request steer where the "+
			"authorization code is delivered", u)
	}
	if strings.Contains(u, "#") {
		return fmt.Errorf("redirect_uri %q contains a fragment, which is not allowed", u)
	}
	if strings.HasPrefix(u, "https://") {
		return nil
	}
	// Loopback for native apps, per RFC 8252. Anything else plaintext would
	// carry an authorization code across the network in the clear.
	if strings.HasPrefix(u, "http://127.0.0.1") || strings.HasPrefix(u, "http://[::1]") ||
		strings.HasPrefix(u, "http://localhost") {
		return nil
	}
	// A private-use scheme, also RFC 8252: com.example.app:/callback
	if i := strings.Index(u, ":"); i > 0 && strings.Contains(u[:i], ".") {
		return nil
	}
	return fmt.Errorf("redirect_uri %q must be https, a loopback address, or a "+
		"private-use scheme", u)
}

// displayNameFor keeps a registered name usable and unsurprising.
//
// The name reaches a consent screen, so it is bounded and stripped of control
// characters. It is NOT sanitised into something trustworthy -- it cannot be,
// since a stranger chose it -- which is why the consent screen shows the
// client_id beside it.
func displayNameFor(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if name == "" {
		return "Unnamed application"
	}
	if len([]rune(name)) > 60 {
		return string([]rune(name)[:60])
	}
	return name
}

func intersectScopes(want, allowed []string) []string {
	if len(want) == 0 {
		return allowed
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []string
	for _, w := range want {
		if ok[w] {
			out = append(out, w)
		}
	}
	return out
}

func sha256Sum(v string) []byte {
	s := sha256.Sum256([]byte(v))
	return s[:]
}
