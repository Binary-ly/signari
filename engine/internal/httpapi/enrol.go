package httpapi

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/qr"
	"signari.dev/engine/internal/store"
)

// Self-service TOTP enrolment.
//
// Two rules shape everything here.
//
// FIRST: enrolment requires a LIVE session, and re-authentication is required to
// turn a factor off. Adding a second factor from a hijacked session is a
// nuisance; REMOVING one is how an attacker with a stolen cookie makes their
// access permanent, so the two directions are not symmetrical and must not be
// guarded identically.
//
// SECOND: a credential is unusable until confirmed. The secret is stored the
// moment it is generated -- otherwise it would have to live in a cookie or a
// hidden form field, which is worse -- but `confirmed_at` stays NULL until the
// user proves their app holds the same secret. A scan that silently failed must
// not lock anyone out of their own account.

// currentSession resolves the signed-in user for an account-management request.
func (s *Server) currentSession(r *http.Request) (sid, userID, orgID string, ok bool) {
	cookie := sessionCookie(r)
	if cookie == "" {
		return "", "", "", false
	}
	ctx := r.Context()
	sid, live, err := store.ResolveSessionCookie(ctx, s.db, store.HashToken(cookie))
	if err != nil || !live || sid == "" {
		return "", "", "", false
	}
	if err := s.db.QueryRow(ctx,
		`SELECT user_id::text, org_id::text FROM core.sessions WHERE sid = $1`, sid).
		Scan(&userID, &orgID); err != nil {
		return "", "", "", false
	}
	return sid, userID, orgID, true
}

// handleTOTPStart generates a secret and shows it for enrolment.
func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	secret, encoded, err := mfa.GenerateSecret()
	if err != nil {
		s.log.Error("generating a TOTP secret", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := store.EnrollTOTP(ctx, tx, userID, orgID, secret,
		mfa.DefaultDigits, mfa.DefaultPeriod, s.cfg.Root); err != nil {
		s.log.Error("enrolling TOTP", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The label is the ORGANISATION's name, not the product's. It is what appears
	// on the user's phone beside a six-digit code, and they recognise the company
	// they signed in to -- not the identity software the company happens to run.
	label := s.orgLabel(ctx, orgID)
	account := s.accountLabel(ctx, userID)

	uri := mfa.ProvisioningURI(label, account, encoded, mfa.DefaultDigits, mfa.DefaultPeriod)

	// The QR code is a convenience, not the credential. If it fails to build, the
	// page still shows the key for manual entry rather than failing enrolment --
	// losing the ability to turn on a second factor is a far worse outcome than
	// losing the square.
	var qrSVG string
	if code, qerr := qr.Encode([]byte(uri)); qerr == nil {
		qrSVG = code.SVG(4, 4)
	} else {
		s.log.Warn("rendering the TOTP QR code", "err", qerr)
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.renderPage(w, enrolPage, map[string]any{
		"Secret": grouped(encoded),
		// template.URL, because html/template's URL sanitiser only permits known
		// schemes and silently rewrites otpauth:// to "#ZgotmplZ" -- producing a
		// dead link with no error anywhere. Safe to mark: the value is built by
		// net/url from a base32 secret and labels ProvisioningURI has already
		// stripped colons from, so nothing user-supplied reaches it unescaped.
		"URI": template.URL(uri),
		// template.HTML because this is an SVG element we generated ourselves
		// from a matrix of booleans -- there is no user-supplied text anywhere in
		// it, only integers formatted into path coordinates.
		"QR":        template.HTML(qrSVG),
		"CSRF":      csrf,
		"CSRFField": csrfFormField,
	})
}

// handleTOTPConfirm verifies the first code and issues recovery codes.
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	if !checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cred, err := store.LoadTOTP(ctx, tx, userID, s.cfg.Root)
	if err != nil {
		s.log.Info("confirming TOTP without a pending enrolment", "err", err)
		http.Redirect(w, r, "/account/mfa/totp", http.StatusFound)
		return
	}

	counter, verr := mfa.Verify(cred.Secret, r.PostForm.Get("code"), time.Now(),
		cred.Digits, cred.Period, mfa.DefaultSkew, cred.LastCounter)
	if verr != nil {
		// Not a lockout path: a failed CONFIRMATION means the app was scanned
		// wrong, and locking someone out of enrolment for mistyping would be a
		// self-inflicted denial of service.
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, enrolPage, map[string]any{
			"Secret": "", "URI": "", "CSRF": csrf, "CSRFField": csrfFormField,
			"Error": "That code did not match. Check your authenticator app and try again.",
		})
		return
	}

	if err := store.RecordTOTPSuccess(ctx, tx, userID, counter); err != nil {
		s.log.Error("confirming TOTP", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Recovery codes are generated WITH the factor, not offered afterwards.
	// Enrolment that leaves them to a later optional step is how a lost phone
	// becomes an unrecoverable account -- and the pressure that creates is what
	// turns a help desk into the weakest authentication path in the system.
	codes, err := store.GenerateRecoveryCodes(ctx, tx, userID, orgID, 10)
	if err != nil {
		s.log.Error("generating recovery codes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := audit.Write(ctx, tx, audit.Event{
		Type: "mfa.totp_enrolled", OrgID: orgID, SubjectID: userID,
		CorrelationID: correlationID(ctx),
		Detail:        map[string]any{"recovery_codes_issued": len(codes)},
	}); err != nil {
		s.log.Error("auditing TOTP enrolment", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Shown ONCE. Only hashes are stored, so this page cannot be reproduced --
	// which is the point: a system that can show a user their recovery codes
	// again can show them to whoever reads the database.
	s.renderPage(w, recoveryPage, map[string]any{"Codes": codes})
}

func (s *Server) orgLabel(ctx context.Context, orgID string) string {
	var name string
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(display_name, slug) FROM core.organizations WHERE id = $1::uuid`,
		orgID).Scan(&name); err != nil || strings.TrimSpace(name) == "" {
		return "Signari"
	}
	return name
}

func (s *Server) accountLabel(ctx context.Context, userID string) string {
	var email, username string
	if err := s.db.QueryRow(ctx,
		`SELECT COALESCE(email,''), COALESCE(username,'') FROM core.users WHERE id = $1::uuid`,
		userID).Scan(&email, &username); err != nil {
		return userID
	}
	if email != "" {
		return email
	}
	if username != "" {
		return username
	}
	return userID
}

// grouped breaks a base32 secret into readable blocks for manual entry, which is
// what people fall back to when a camera will not focus.
func grouped(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Server) renderPage(w http.ResponseWriter, t *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		`default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	_ = t.Execute(w, data)
}

const pageCSS = `body{font-family:system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem}
code{background:#f4f4f5;padding:.2rem .4rem;border-radius:3px}
.qr{margin:1rem 0;max-width:220px}
.qr svg{width:100%;height:auto;display:block}
details{margin:1rem 0}
summary{cursor:pointer;font-size:.9rem}
.secret{font-size:1.1rem;letter-spacing:.1em;display:block;padding:.75rem;background:#f4f4f5;
  border-radius:4px;margin:.5rem 0;word-break:break-all}
.err{color:#b00020}.hint{color:#666;font-size:.9rem}
ol{columns:2;font-family:ui-monospace,monospace;line-height:1.9}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem}
input{padding:.5rem;font-size:1.25rem;letter-spacing:.2em;width:100%}`

var enrolPage = template.Must(template.New("enrol").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set up two-factor authentication</title><style>` + pageCSS + `</style></head>
<body>
<h1>Set up two-factor authentication</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Secret}}
<p>Scan this with your authenticator app:</p>
<div class="qr">{{.QR}}</div>
<details>
<summary>Can&rsquo;t scan it?</summary>
<p>Type this key into your authenticator app instead:</p>
<code class="secret">{{.Secret}}</code>
<p class="hint">Or open <a href="{{.URI}}">this link</a> on the device with your
authenticator app.</p>
</details>
{{end}}
<form method="POST" action="/account/mfa/totp">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<label for="c">Enter the 6-digit code it shows</label>
<input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
<button type="submit">Turn on two-factor authentication</button>
</form>
</body></html>`))

var recoveryPage = template.Must(template.New("recovery").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Your recovery codes</title><style>` + pageCSS + `</style></head>
<body>
<h1>Two-factor authentication is on</h1>
<p><strong>Save these recovery codes now.</strong> Each one works once, and this is
the only time they can be shown &mdash; only hashes are stored, so nobody can
retrieve them for you later.</p>
<ol>{{range .Codes}}<li>{{.}}</li>{{end}}</ol>
<p class="hint">Keep them somewhere other than the device with your authenticator app.
If you lose both, you lose the account.</p>
</body></html>`))
