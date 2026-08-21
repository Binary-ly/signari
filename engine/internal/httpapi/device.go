package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/store"
)

// The device authorization grant, RFC 8628.
//
//	POST /oauth2/device_authorization   the device asks
//	GET|POST /device                    the person approves
//	POST /oauth2/token                  the device polls (grant_type=...device_code)

const (
	// deviceCodeLifetime is deliberately short. RFC 8628 suggests values around
	// this; some implementations allow hours, which widens the phishing window
	// for no benefit -- nobody legitimately takes an hour to type eight letters.
	deviceCodeLifetime = 10 * time.Minute
	// devicePollInterval is the starting value. It grows on slow_down.
	devicePollInterval = 5

	// deviceAttemptsPerWindow bounds guesses from one address.
	//
	// A user code is 8 characters from a 21-letter alphabet: about 35 bits, or
	// 3.8e10 possibilities. At 20 attempts per 10 minutes one address needs
	// roughly 36,000 years of continuous guessing to cover a single percent of
	// the space, and codes live for ten minutes. Generous enough that a person
	// mistyping a code off a television never meets it.
	deviceAttemptsPerWindow = 20

	// deviceAttemptsPerUser is RFC 8628 §5.1's budget, applied where it bites.
	//
	// 21^8 / 2^32 = 8.8, so EIGHT attempts per code lifetime is the largest
	// budget that keeps a single account at or below the 2^-32 probability §5.1
	// works towards. See the comment at the limiter for why the per-address
	// bucket cannot carry this property on its own.
	//
	// Ten was written here first, on the reasoning that 2^-31.8 is "2^-32 to
	// within a rounding". The test that pins this does the sum and disagreed, and
	// the test is right: a budget chosen for tidiness is exactly the kind of
	// number that drifts, and the specification names a threshold rather than a
	// neighbourhood. Eight is still far more than a person approving a television
	// ever needs -- nobody mistypes an eight-character code eight times.
	deviceAttemptsPerUser = 8

	deviceAttemptWindow = 10 * time.Minute
)

// handleDeviceAuthorization answers a device asking to be authorised.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Credentials resolved exactly as at the token endpoint. RFC 8628 §3.1: a
	// confidential client authenticates as described in RFC 6749 §3.2.1, which
	// is the token endpoint's rule -- so client_secret_basic has to work here,
	// and it did not.
	creds, cerr := oauth.ParseClientCredentials(r.Header, r.PostForm)
	if cerr != nil {
		writeError(w, cerr.Status, cerr.Code, cerr.Description)
		return
	}
	clientID := creds.ClientID
	c, err := s.lookupClient(ctx, clientID)
	if err != nil || c == nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	// A confidential client authenticates here exactly as it would at the token
	// endpoint. Skipping it would let anyone start a device flow in its name and
	// phish a user code that names a trusted application.
	if c.Type == "confidential" {
		if err := s.authenticateConfidentialClient(ctx, r, c, creds.ClientSecret); err != nil {
			s.log.Info("device authorization: client authentication failed",
				"client_id", clientID, "err", err)
			writeError(w, http.StatusUnauthorized, "invalid_client",
				"client authentication failed")
			return
		}
	}

	// Registered for THIS grant, not merely registered.
	//
	// RFC 6749 §5.2's `unauthorized_client` exists for this, and the check
	// belongs here as well as at the token endpoint: without it a client that may
	// not complete a device flow can still start one, which means it can still
	// display a user code to a person and ask them to approve it. The phishing
	// value of a device flow is in the verification screen, not in the token.
	if !c.AllowsGrantType(oauth.GrantTypeDeviceCode) {
		s.log.Info("device authorization refused: client is not registered for the grant",
			"client_id", clientID, "correlation_id", correlationID(ctx))
		writeError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not registered for the device grant")
		return
	}

	scope := strings.TrimSpace(r.PostForm.Get("scope"))

	if scope != "" {
		if unknown := c.UnknownScopes(splitScopes(scope)); len(unknown) > 0 {
			s.log.Info("device authorization requested an unregistered scope",
				"client_id", clientID, "scope", unknown[0],
				"correlation_id", correlationID(ctx))
			writeError(w, http.StatusBadRequest, "invalid_scope",
				"client is not registered for scope "+unknown[0])
			return
		}
	}
	// Never nil: a nil slice is sent as SQL NULL, and an explicit NULL overrides
	// the column default, so the NOT NULL constraint rejects it.
	resource := r.PostForm["resource"]
	if resource == nil {
		resource = []string{}
	}

	deviceCode, err := newSID()
	if err != nil {
		s.log.Error("generating a device code", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	userCode, err := oauth.NewUserCode()
	if err != nil {
		s.log.Error("generating a user code", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	if _, err := store.CreateDeviceAuthorization(ctx, s.db, c.OrgID, c.ClientID, scope,
		resource, store.HashToken(deviceCode), store.HashToken(userCode),
		devicePollInterval, deviceCodeLifetime); err != nil {
		s.log.Error("recording a device authorization", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	verification := s.cfg.Issuer + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": deviceCode,
		"user_code":   oauth.FormatUserCode(userCode),
		// Both forms. verification_uri is what a person types; the _complete
		// variant carries the code so a QR code needs no typing at all, which is
		// the difference between a usable television login and a hated one.
		"verification_uri":          verification,
		"verification_uri_complete": verification + "?user_code=" + oauth.FormatUserCode(userCode),
		"expires_in":                int(deviceCodeLifetime.Seconds()),
		"interval":                  devicePollInterval,
	})
}

// handleDeviceVerification is where the person types the code.
func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Signing in first. The approval must be attributable to somebody, and
	// bouncing through login here is what makes that true.
	sid, userID, orgID, ok := s.currentSession(r)
	if !ok {
		back := "/device"
		if code := r.URL.Query().Get("user_code"); code != "" {
			back += "?user_code=" + template.URLQueryEscaper(code)
		}
		http.Redirect(w, r, parkLogin(back), http.StatusSeeOther)
		return
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	render := func(userCode, errMsg string, d *store.DeviceAuthorization) {
		data := map[string]any{
			"UserCode":  userCode,
			"Error":     errMsg,
			"CSRF":      csrf,
			"CSRFField": csrfFormField,
		}
		if d != nil {
			data["Confirm"] = true
			data["ClientName"] = s.clientDisplayName(ctx, d.ClientID)
			data["Scopes"] = strings.Fields(d.Scope)
		}
		s.renderPage(w, r, devicePage, data)
	}

	if r.Method == http.MethodGet {
		render(r.URL.Query().Get("user_code"), "", nil)
		return
	}

	// RFC 8628 §5.1: rate limit the user interaction endpoint. A user code is
	// short enough to type and therefore short enough to guess; this is what
	// makes guessing expensive, since a wrong guess names no record to charge.
	//
	// Limited per ADDRESS, not globally. This was one shared bucket of 3/s with
	// a burst of 10 for the entire deployment, which made the defence into an
	// attack: anybody sending four requests a second held it empty, and every
	// legitimate person in every organisation was refused with "too many
	// attempts" while trying to sign in a television. An unauthenticated denial
	// of service on the whole device flow, costing the attacker nothing.
	//
	// Per-address is also strictly better at the job the limit exists for.
	// Guessing comes from somewhere, so charging the source both slows the
	// guesser and leaves everybody else unaffected.
	if res, err := store.AllowRate(ctx, s.db, "device:ip:"+clientIP(r),
		deviceAttemptsPerWindow, deviceAttemptWindow); err != nil {
		// Fail CLOSED. This endpoint's whole protection against guessing an
		// eight-character code is the limit; serving it unlimited because the
		// database is unhappy removes the defence exactly when nobody is
		// watching.
		s.log.Error("device rate limit unavailable", "err", err)
		render("", "Try again in a moment.", nil)
		return
	} else if !res.Allowed {
		render("", "Too many attempts from this address. Wait a few minutes.", nil)
		return
	}

	// And per ACCOUNT, which is the bucket the specification's arithmetic
	// actually describes.
	//
	// §5.1 works the sum out: an 8-character base-20 code has ~34.5 bits, and
	// "the rate-limiting interval and validity period would need to only allow 5
	// attempts in order to get the same 2^-32 probability of success by random
	// guessing". Ours is 8 characters from a 21-letter alphabet -- 21^8, or
	// 2^35.14 -- so the equivalent budget is 21^8 / 2^32, which is 8.8.
	//
	// The per-address limit does not bound that sum, because an address is not a
	// scarce resource. One attacker behind a thousand proxies had 20 guesses
	// each, capped only by the global backstop at 200/s -- around 120,000 guesses
	// per ten-minute code lifetime, which is 2^-18 against this code space rather
	// than 2^-32.
	//
	// An ACCOUNT is scarce, because this page requires a signed-in session: §5.1's
	// attack is "approve the authorization grant with their own credentials", so
	// the guesser necessarily has one. Charging the account is what turns the
	// specification's arithmetic into something the code enforces.
	//
	// Eight, which is floor(21^8 / 2^32) and therefore the largest budget that
	// satisfies the section. A person approving a television mistypes once or
	// twice, never eight times.
	if res, err := store.AllowRate(ctx, s.db, "device:user:"+userID,
		deviceAttemptsPerUser, deviceAttemptWindow); err != nil {
		s.log.Error("device per-user rate limit unavailable", "err", err)
		render("", "Try again in a moment.", nil)
		return
	} else if !res.Allowed {
		render("", "Too many attempts. Wait a few minutes and try again.", nil)
		return
	}

	// The global bucket stays as a backstop against a distributed attempt, but
	// widened so it is no longer reachable by one address on its own.
	if !s.device.allow() {
		render("", "Too many attempts just now. Wait a moment and try again.", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		render("", "That form could not be read.", nil)
		return
	}
	if !checkCSRF(r) {
		render("", "That form expired. Try again.", nil)
		return
	}

	typed := oauth.NormalizeUserCode(r.PostForm.Get("user_code"))
	if !oauth.ValidUserCodeShape(typed) {
		// Not a failed attempt against any record: this string cannot match one,
		// so counting it would let an attacker exhaust somebody else's budget.
		render(r.PostForm.Get("user_code"),
			"That code does not look right. Check it and try again.", nil)
		return
	}

	d, err := store.LookupUserCode(ctx, s.db, store.HashToken(typed))
	if err != nil {
		render(r.PostForm.Get("user_code"),
			"That code is not valid, or it has expired. Codes last ten minutes.", nil)
		return
	}
	if d.OrgID != orgID {
		// Cross-tenant approval. Answered exactly like an unknown code so the
		// screen cannot be used to discover which codes exist elsewhere.
		render(r.PostForm.Get("user_code"),
			"That code is not valid, or it has expired. Codes last ten minutes.", nil)
		return
	}

	switch r.PostForm.Get("decision") {
	case "approve":
		if err := store.ApproveDeviceAuthorization(ctx, s.db, d.ID, userID, sid); err != nil {
			render("", "That request is no longer waiting. Start again on the device.", nil)
			return
		}
		s.log.Info("device authorization approved", "client_id", d.ClientID,
			"user_id", userID, "correlation_id", correlationID(ctx))
		s.renderPage(w, r, devicePage, map[string]any{"Done": true})
	case "deny":
		if err := store.DenyDeviceAuthorization(ctx, s.db, d.ID); err != nil {
			s.log.Error("denying a device authorization", "err", err)
		}
		s.renderPage(w, r, devicePage, map[string]any{"Denied": true})
	default:
		// First POST: the code was right, so show what is being authorised and
		// ask. The confirmation step is the only place a phished user is told
		// what they are actually approving.
		render(oauth.FormatUserCode(typed), "", d)
	}
}

// handleDeviceCodeGrant is the token endpoint's device_code branch.
func (s *Server) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()

	deviceCode := r.PostForm.Get("device_code")
	if deviceCode == "" {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_request",
			Description: "device_code is required", Status: http.StatusBadRequest})
		return
	}

	d, err := store.PollDeviceCode(ctx, s.db, store.HashToken(deviceCode), clientID, "device")
	switch {
	case errors.Is(err, store.ErrDeviceCodePending):
		writeTokenError(w, &oauth.TokenError{Code: "authorization_pending",
			Description: "the user has not yet approved this device",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeSlowDown):
		writeTokenError(w, &oauth.TokenError{Code: "slow_down",
			Description: "polling faster than the interval; wait five seconds longer",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeDenied):
		writeTokenError(w, &oauth.TokenError{Code: "access_denied",
			Description: "the user refused this device", Status: http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeWrongClient):
		s.log.Info("device code presented by the wrong client", "presented_by", clientID,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "invalid_grant",
			Description: "this device code was not issued to this client",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeSessionGone):
		// The person did approve; the session they approved from has since ended.
		// `access_denied` rather than `expired_token`, because the authorization
		// was withdrawn rather than timed out — RFC 8628 §3.5 gives the code for
		// "the end user denied", and a revoked session is the closest true
		// statement: the authority behind the approval is gone.
		s.log.Info("approval refused: the session behind it has ended",
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "access_denied",
			Description: "the session this request was approved from has ended",
			Status:      http.StatusBadRequest})
		return
	case errors.Is(err, store.ErrDeviceCodeUnknown):
		// Unknown, expired and already-redeemed are one answer. RFC 8628 defines
		// expired_token, and it is used here only for codes we can still see are
		// ours -- which, since expiry is enforced in the query, means never. One
		// indistinguishable answer beats a taxonomy that leaks.
		writeTokenError(w, &oauth.TokenError{Code: "expired_token",
			Description: "this device code is not valid; start again on the device",
			Status:      http.StatusBadRequest})
		return
	case err != nil:
		s.log.Error("polling a device code", "err", err)
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	s.issueDeviceTokens(w, r, d)
}

var devicePage = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect a device</title><style>` + pageCSS + `</style></head>
<body>
{{if .Done}}
<h1>Device connected</h1>
<p>You can put this away and go back to the device.</p>
{{else if .Denied}}
<h1>Request refused</h1>
<p>Nothing was granted. If you did not start this, somebody else may have asked
you to enter that code &mdash; it is worth telling whoever runs your systems.</p>
{{else if .Confirm}}
<h1>Allow this device?</h1>
<p><strong>{{.ClientName}}</strong> is asking to sign in as you on a device.</p>
{{if .Scopes}}<p>It will be able to:</p><ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>{{end}}
<p class="hint">Only continue if you started this yourself, on a device in front
of you. Nobody legitimate will ask you to enter a code they sent you.</p>
<form method="POST" action="/device">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<input type="hidden" name="user_code" value="{{.UserCode}}">
<button type="submit" name="decision" value="approve">Allow</button>
<button type="submit" name="decision" value="deny" class="secondary">Refuse</button>
</form>
{{else}}
<h1>Connect a device</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<p>Enter the code shown on your device.</p>
<form method="POST" action="/device">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<label for="uc">Code</label>
<input id="uc" name="user_code" value="{{.UserCode}}" autocomplete="off"
       autocapitalize="characters" spellcheck="false" autofocus required>
<button type="submit">Continue</button>
</form>
{{end}}
</body></html>`))

// clientDisplayName is what the person is asked to trust. Falls back to the id,
// never to something invented.
func (s *Server) clientDisplayName(ctx context.Context, clientID string) string {
	var name string
	if err := s.db.QueryRow(ctx,
		`SELECT display_name FROM core.clients WHERE client_id = $1`, clientID).Scan(&name); err != nil {
		return clientID
	}
	if strings.TrimSpace(name) == "" {
		return clientID
	}
	return fmt.Sprintf("%s (%s)", name, clientID)
}

// issueDeviceTokens mints the token set for an approved device.
//
// Goes through mintSet like every other grant, so a device token is subject to
// the same DPoP binding, resource indicators, group claims and audit trail. A
// second minting path would be a second place for those to be forgotten.
func (s *Server) issueDeviceTokens(w http.ResponseWriter, r *http.Request,
	d *store.DeviceAuthorization) {

	ctx := r.Context()
	c, err := s.lookupClient(ctx, d.ClientID)
	if err != nil || c == nil {
		writeTokenError(w, &oauth.TokenError{Code: "invalid_client",
			Description: "unknown client", Status: http.StatusUnauthorized})
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	scopes := splitScopes(d.Scope)
	if len(scopes) == 0 {
		scopes = c.Scopes
	}

	// No nonce: there was no authorization request from a browser to bind one to.
	// An id_token here asserts the authentication the person performed at the
	// verification screen, which mintSet reads from the session.
	resp, _, err := s.mintSet(ctx, tx, c, d.OrgID, d.UserID, d.SID, "", scopes, d.Resource,
		// The device authorization endpoint does not accept authorization_details
		// today, so there are none to carry. nil rather than an empty slice: the
		// grant has no rich permissions, it does not have zero of them.
		nil, "")
	if err != nil {
		s.log.Error("minting tokens for a device grant", "err", err,
			"correlation_id", correlationID(ctx))
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeTokenError(w, &oauth.TokenError{Code: "server_error",
			Status: http.StatusInternalServerError})
		return
	}

	s.log.Info("device grant redeemed", "client_id", d.ClientID, "user_id", d.UserID,
		"correlation_id", correlationID(ctx))
	writeJSON(w, http.StatusOK, resp)
}
