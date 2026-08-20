package httpapi

import (
	"strings"

	"html/template"
	"net/http"
	"net/url"
	"signari.dev/engine/internal/rar"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// The consent screen.
//
// Three rules decide whether it appears, and each exists because the alternative
// makes consent worthless:
//
//  1. Only the scopes NOT already granted are shown. Re-listing what the user
//     approved last month trains them to click through without reading, which is
//     the failure mode every consent screen dies of.
//  2. First-party clients skip it. "Acme wants to access your Acme account", on
//     Acme's own login page, teaches the same habit.
//  3. prompt=consent forces it regardless. A client that wants to re-confirm --
//     before a payment, say -- must be able to.

// scopeDescriptions turns scope names into something a person can act on.
//
// A screen listing `openid profile email offline_access` asks the user to
// approve strings they have no way to evaluate. If we cannot say plainly what a
// scope grants, we have no business asking anyone to consent to it.
var scopeDescriptions = map[string]string{
	"profile":        "See your name and username",
	"email":          "See your email address",
	"offline_access": "Stay signed in and access your account while you are away",
	"address":        "See your postal address",
	"phone":          "See your phone number",
}

func describeScope(s string) string {
	if d, ok := scopeDescriptions[s]; ok {
		return d
	}
	// An unknown scope is shown verbatim rather than hidden or glossed. A user
	// approving something we cannot describe should at least see its name.
	return s
}

type scopeItem struct{ Name, Description string }

// detailItem is one RFC 9396 authorization detail, rendered for a person.
type detailItem struct {
	Type string
	Rows []detailRow
}

type detailRow struct{ Label, Value string }

// describeDetails turns authorization details into something a user can weigh.
//
// §3.1: "When gathering user consent, the AS MUST present the merged set of
// requirements represented by the authorization request." Merged means scopes
// AND details -- showing one and not the other describes a different request
// from the one being authorized.
//
// The values are shown verbatim, not summarised. §2.2 says the allowable values
// "are determined by the API being protected", so this server does not know that
// `instructedAmount` is money or that `creditorAccount` is where it goes. What it
// can do is show every field it was given and let the person read it; a screen
// that paraphrased a payment it did not understand would be worse than one that
// did not try.
func describeDetails(details []rar.Detail) []detailItem {
	out := make([]detailItem, 0, len(details))
	for _, d := range details {
		item := detailItem{Type: d.Type}
		add := func(label string, vals []string) {
			if len(vals) > 0 {
				item.Rows = append(item.Rows, detailRow{label, strings.Join(vals, ", ")})
			}
		}
		add("Actions", d.Actions)
		add("Resources", d.Locations)
		add("Data", d.Datatypes)
		add("Privileges", d.Privileges)
		if d.Identifier != "" {
			item.Rows = append(item.Rows, detailRow{"Identifier", d.Identifier})
		}
		out = append(out, item)
	}
	return out
}

// needsConsent decides whether to interrupt the flow.
func (s *Server) needsConsent(r *http.Request, c *clients.Client, userID string,
	req oauth.AuthzRequest) (store.ConsentDecision, bool, error) {

	requested := splitScopes(req.Scope)

	// prompt=consent is checked FIRST, before the first-party exemption: a client
	// explicitly asking to re-confirm must get the screen even if it normally
	// skips it, because the request is about this action, not this client.
	if oauth.HasPrompt(req.Prompt, oauth.PromptConsent) {
		d, err := store.CheckConsent(r.Context(), s.db, userID, c.ClientID, requested)
		if err != nil {
			return d, false, err
		}
		// Everything is shown, not just what is missing: the client asked the
		// user to look again.
		d.Missing = nil
		for _, sc := range requested {
			if sc != "openid" {
				d.Missing = append(d.Missing, sc)
			}
		}
		return d, len(d.Missing) > 0, nil
	}

	// Rich authorization details ALWAYS prompt, and they are checked before the
	// first-party exemption on purpose.
	//
	// Stored consent is keyed on scope names. An authorization detail is not a
	// scope: it carries the particulars of one transaction -- this amount, this
	// account, this document. A user who once approved the scope `payments` has
	// approved a capability, never a payment, so letting a stored grant satisfy a
	// detail would auto-approve every later transfer to any account, silently and
	// with no screen. The first-party exemption has the same hole: it says the
	// relationship is trusted, which cannot be true of a transaction that did not
	// exist when the relationship was established.
	//
	// So details are the one thing here that no prior decision can pre-approve.
	if len(req.AuthorizationDetails) > 0 {
		d, err := store.CheckConsent(r.Context(), s.db, userID, c.ClientID, requested)
		if err != nil {
			return d, false, err
		}
		return d, true, nil
	}

	if c.FirstParty {
		return store.ConsentDecision{Granted: true}, false, nil
	}

	d, err := store.CheckConsent(r.Context(), s.db, userID, c.ClientID, requested)
	return d, !d.Granted, err
}

// renderConsent shows what is being asked for.
func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request,
	c *clients.Client, d store.ConsentDecision, details []rar.Detail, authzQuery string) {

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		s.log.Error("minting csrf token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "unavailable")
		return
	}

	items := make([]scopeItem, 0, len(d.Missing))
	for _, sc := range d.Missing {
		items = append(items, scopeItem{Name: sc, Description: describeScope(sc)})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		`default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`)
	// Clickjacking matters more here than anywhere else in the product: an
	// invisible framed consent screen with a decoy button over "Allow" is how a
	// user grants access they never saw.
	w.Header().Set("X-Frame-Options", "DENY")

	_ = consentPage.Execute(w, map[string]any{
		"Client": c.DisplayName, "ClientID": c.ClientID,
		"Scopes": items, "Details": describeDetails(details), "Authz": authzQuery,
		"CSRF": csrf, "CSRFField": csrfFormField,
	})
}

// handleConsentPost records the decision and resumes or aborts the flow.
func (s *Server) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		// Without this, a page on another site could submit "Allow" on the user's
		// behalf -- consent forged rather than given.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	authzQuery := r.PostForm.Get("authz")

	// The client is read from the parked authorization query, NOT from a
	// separate form field.
	//
	// Both were submitted, and two fields that must agree eventually will not.
	// A form saying client_id=B while the authz query says client_id=A records
	// consent for B and then resumes the flow for A: the user is shown one
	// application's name, agrees to it, and a different application is the one
	// that stops asking. The query is authoritative because it is the value the
	// flow actually continues with.
	//
	// Found by a request that omitted the field entirely: consent was recorded
	// for the empty string, which the foreign key refused and the handler
	// reported as an internal error.
	clientID := clientFromAuthz(authzQuery)
	if clientID == "" {
		http.Error(w, "that consent request is incomplete", http.StatusBadRequest)
		return
	}
	if submitted := r.PostForm.Get("client_id"); submitted != "" && submitted != clientID {
		s.log.Warn("consent form named a different client than the request",
			"form", submitted, "request", clientID,
			"correlation_id", correlationID(ctx))
		http.Error(w, "that consent request could not be verified", http.StatusBadRequest)
		return
	}

	if r.PostForm.Get("decision") != "allow" {
		// RFC 6749 §4.1.2.1: a refusal is reported to the client, not swallowed.
		// A user who clicks Deny and lands on a blank page has no idea whether it
		// worked, and the client waits forever.
		s.auditDetached(ctx, audit.Event{
			Type: "oauth.consent_denied", OrgID: orgID, SubjectID: userID, ClientID: clientID,
			CorrelationID: correlationID(ctx),
		})
		s.denyToClient(w, r, authzQuery)
		return
	}

	scopes := r.PostForm["scope"]
	if len(scopes) == 0 {
		s.denyToClient(w, r, authzQuery)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.RecordConsent(ctx, tx, userID, clientID, scopes); err != nil {
		s.log.Error("recording consent", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := audit.Write(ctx, tx, audit.Event{
		Type: "oauth.consent_granted", OrgID: orgID, SubjectID: userID, ClientID: clientID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"scopes": scopes},
	}); err != nil {
		s.log.Error("auditing consent", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, oidc.PathAuthorize+"?"+authzQuery, http.StatusFound)
}

// denyToClient returns access_denied to the client's redirect_uri.
func (s *Server) denyToClient(w http.ResponseWriter, r *http.Request, authzQuery string) {
	req := oauth.ParseAuthz(parseQuery(authzQuery))
	s.writeAuthzError(w, r, req, &oauth.AuthzError{
		Code:        "access_denied",
		Description: "the user refused the request",
		Disposition: oauth.DispositionRedirect,
	})
}

// parseQuery re-parses the parked authorization request.
//
// url.ParseQuery, not hand-rolled splitting: the parked query carries a
// redirect_uri and a state that are percent-encoded, and getting the decoding
// subtly wrong here would mean denying to a slightly different URI than the one
// validated at /authorize.
func parseQuery(q string) url.Values {
	vals, err := url.ParseQuery(q)
	if err != nil {
		return url.Values{}
	}
	return vals
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize {{.Client}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem}
h1{font-size:1.3rem}ul{list-style:none;padding:0}
li{padding:.6rem .75rem;background:#f4f4f5;border-radius:4px;margin:.4rem 0}
.scope{color:#666;font-size:.8rem;display:block}
.detail{background:#fff;border:1px solid #d4d4d8;border-radius:4px;padding:.7rem .75rem;margin:.4rem 0}
.dtype{font-size:.8rem;color:#666;display:block;margin-bottom:.35rem}
.drow{display:flex;gap:.5rem;font-size:.9rem;padding:.1rem 0}
.dlabel{color:#666;min-width:6.5rem}
.dval{font-weight:500;word-break:break-word}
.row{display:flex;gap:.75rem;margin-top:1.5rem}
button{flex:1;padding:.7rem 1rem;font-size:1rem}
.allow{background:#18181b;color:#fff;border:0;border-radius:4px}
.deny{background:#fff;border:1px solid #d4d4d8;border-radius:4px}</style></head>
<body>
<h1><strong>{{.Client}}</strong> wants access to your account</h1>
{{if .Scopes}}
<p>It is asking to:</p>
<ul>
{{range .Scopes}}<li>{{.Description}}<span class="scope">{{.Name}}</span></li>{{end}}
</ul>
{{end}}
{{if .Details}}
<p>And to perform this specific operation:</p>
{{range .Details}}<div class="detail">
<span class="dtype">{{.Type}}</span>
{{range .Rows}}<div class="drow"><span class="dlabel">{{.Label}}</span><span class="dval">{{.Value}}</span></div>{{end}}
</div>{{end}}
{{end}}
<form method="POST" action="/consent">
<input type="hidden" name="authz" value="{{.Authz}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
{{range .Scopes}}<input type="hidden" name="scope" value="{{.Name}}">{{end}}
<div class="row">
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
<button class="allow" type="submit" name="decision" value="allow">Allow</button>
</div>
</form>
</body></html>`))

// clientFromAuthz reads the client id out of a parked authorization query.
func clientFromAuthz(authzQuery string) string {
	q, err := url.ParseQuery(authzQuery)
	if err != nil {
		return ""
	}
	return q.Get("client_id")
}
