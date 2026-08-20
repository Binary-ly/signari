package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"signari.dev/engine/internal/mail"
	"strings"
	"time"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/brand"
	"signari.dev/engine/internal/mfa"
	"signari.dev/engine/internal/qr"
	"signari.dev/engine/internal/sms"
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
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
	s.renderPage(w, r, enrolPage, map[string]any{
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
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
		http.Redirect(w, r, "/account/mfa/totp", http.StatusSeeOther)
		return
	}

	counter, verr := mfa.Verify(cred.Secret, r.PostForm.Get("code"), time.Now(),
		cred.Digits, cred.Period, mfa.DefaultSkew, cred.LastCounter)
	if verr != nil {
		// Not a lockout path: a failed CONFIRMATION means the app was scanned
		// wrong, and locking someone out of enrolment for mistyping would be a
		// self-inflicted denial of service.
		csrf, _ := s.csrfToken(w, r)
		s.renderPage(w, r, enrolPage, map[string]any{
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
	s.renderPage(w, r, recoveryPage, map[string]any{"Codes": codes})
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

// renderPage writes one of the user-facing pages, with the instance's brand.
//
// The brand is injected HERE rather than by each template, so no page can be
// missed. A sign-in page that ignores the brand while the consent page honours
// it does not look like a missing feature -- it looks like the deployment has
// been tampered with, which is the opposite of what branding is for.
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request,
	t *template.Template, data map[string]any) {

	b := s.brandNow(r.Context())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// img-src is widened ONLY when a logo is actually configured. An unbranded
	// deployment keeps default-src 'none', so the permission exists exactly
	// where it is used rather than everywhere in case it is needed.
	w.Header().Set("Content-Security-Policy",
		`default-src 'none'; style-src 'unsafe-inline';`+brandImgSrc(b)+
			` form-action 'self'; frame-ancestors 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")

	if b != nil {
		if data == nil {
			data = map[string]any{}
		}
		data["BrandName"] = b.ProductName
		data["BrandLogo"] = b.LogoURL
		data["BrandSupport"] = b.SupportURL
	}

	writeBranded(w, t, data, b)
}

// writeBranded renders a template and injects the brand's colours.
//
// The colours go into the RENDERED page rather than being referenced by each
// template, so no page can be missed. A sign-in page in the default palette
// followed by a consent page in the customer's colours does not read as a
// missing feature -- it reads as though one of the two pages is not really
// ours, which is the opposite of what branding is for.
func writeBranded(w io.Writer, t *template.Template, data map[string]any, b *brand.Brand) {
	css := ""
	if b != nil {
		css = b.CSS()
	}
	if css == "" {
		_ = t.Execute(w, data)
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return
	}
	page := buf.Bytes()
	// Injected last in <head>, so it overrides the stylesheet above it.
	if i := bytes.LastIndex(page, []byte("</head>")); i >= 0 {
		out := make([]byte, 0, len(page)+len(css)+16)
		out = append(out, page[:i]...)
		out = append(out, "<style>"...)
		out = append(out, css...)
		out = append(out, "</style>"...)
		out = append(out, page[i:]...)
		page = out
	}
	_, _ = w.Write(page)
}

// brandImgSrc is the img-src a brand needs, or "" when it needs none.
//
// Widened only when a logo is actually configured, so an unbranded deployment
// keeps default-src 'none' and the permission exists exactly where it is used.
func brandImgSrc(b *brand.Brand) string {
	if b != nil && b.LogoURL != "" {
		return " img-src https:;"
	}
	return ""
}

// brandNow reads the instance's brand.
//
// Read per render rather than cached at startup, so `signari brand set` takes
// effect immediately. These are sign-in pages, not a hot path, and one indexed
// row by primary key is cheaper than the class of bug where an operator changes
// a colour and cannot tell whether it worked.
func (s *Server) brandNow(ctx context.Context) *brand.Brand {
	if s.cfg.Issuer == "" {
		return nil
	}
	b, err := store.LoadBrandByIssuer(ctx, s.db, s.cfg.Issuer)
	if err != nil {
		s.log.Error("reading the brand", "err", err)
		return nil
	}
	return b
}

const pageCSS = `body{font-family:system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;
  background:var(--brand-background,#fff);color:var(--brand-text,#000)}
a{color:var(--brand-primary,#0645ad)}
.brand{display:block;max-height:2.5rem;margin-bottom:1.5rem}
code{background:#f4f4f5;padding:.2rem .4rem;border-radius:3px}
.qr{margin:1rem 0;max-width:220px}
.qr svg{width:100%;height:auto;display:block}
details{margin:1rem 0}
summary{cursor:pointer;font-size:.9rem}
.secret{font-size:1.1rem;letter-spacing:.1em;display:block;padding:.75rem;background:#f4f4f5;
  border-radius:4px;margin:.5rem 0;word-break:break-all}
.err{color:#b00020}.hint{color:#666;font-size:.9rem}
ol{columns:2;font-family:ui-monospace,monospace;line-height:1.9}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;
  background:var(--brand-primary,#efefef);color:var(--brand-on-primary,#000);
  border:1px solid var(--brand-primary,#767676);border-radius:4px;cursor:pointer}
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

// handleEmailOTPEnrol turns on email as a second factor.
//
// Enrolment requires proving control of the address by entering a code sent to
// it — the same standard the factor will be held to later. Trusting the address
// on the account record instead would let somebody who has stolen a session
// enrol a factor they already control, which is a way of locking the real owner
// out rather than a way of protecting them.
func (s *Server) handleEmailOTPEnrol(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/mfa/email"), http.StatusSeeOther)
		return
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render := func(stage, addr, msg string) {
		s.renderPage(w, r, emailOTPPage, map[string]any{
			"Stage": stage, "Address": addr, "Error": msg,
			"CSRF": csrf, "CSRFField": csrfFormField,
		})
	}

	if r.Method == http.MethodGet {
		var current string
		if err := s.db.QueryRow(ctx,
			`SELECT COALESCE(email,'') FROM core.users WHERE id = $1::uuid`,
			userID).Scan(&current); err != nil {
			s.log.Error("reading the account address", "err", err)
		}
		render("start", current, "")
		return
	}

	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		render("start", "", "That form expired. Try again.")
		return
	}

	switch r.PostForm.Get("step") {
	case "verify":
		tx, terr := s.db.Begin(ctx)
		if terr != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		okCode, verr := store.VerifyEmailOTP(ctx, tx, userID,
			strings.TrimSpace(r.PostForm.Get("code")))
		if verr != nil {
			s.log.Error("verifying an enrolment code", "err", verr)
			render("start", "", "Something went wrong. Try again.")
			return
		}
		if !okCode {
			render("code", r.PostForm.Get("address"),
				"That code did not match, or it has expired.")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}
		s.log.Info("email second factor enrolled", "user_id", userID,
			"correlation_id", correlationID(ctx))
		render("done", "", "")

	default: // send a code to the address being enrolled
		address := strings.TrimSpace(r.PostForm.Get("address"))
		if !strings.Contains(address, "@") || len(address) > 320 {
			render("start", address, "That does not look like an email address.")
			return
		}

		tx, terr := s.db.Begin(ctx)
		if terr != nil {
			render("start", address, "Something went wrong. Try again.")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		if err := store.EnrollEmailOTP(ctx, tx, userID, orgID, address); err != nil {
			s.log.Error("enrolling the email factor", "err", err)
			render("start", address, "Something went wrong. Try again.")
			return
		}
		code, addr, ierr := store.IssueEmailOTP(ctx, tx, userID)
		if errors.Is(ierr, store.ErrEmailOTPTooSoon) {
			render("code", address, "A code was just sent. Check your inbox.")
			return
		}
		if ierr != nil {
			s.log.Error("issuing an enrolment code", "err", ierr)
			render("start", address, "Something went wrong. Try again.")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			render("start", address, "Something went wrong. Try again.")
			return
		}

		if err := s.mailer.Send(ctx, mail.Message{
			To:      addr,
			Subject: "Confirm this address for sign-in codes",
			Body: fmt.Sprintf("Your confirmation code is %s\n\n"+
				"It expires in %d minutes.\n\n"+
				"If you did not ask to use this address for sign-in codes, "+
				"somebody may be signed in to your account. Change your password.\n",
				code, int(store.EmailOTPLifetime.Minutes())),
		}); err != nil {
			s.log.Error("sending an enrolment code", "err", err)
			// Said out loud HERE, unlike at sign-in: this person is already
			// authenticated, so there is nothing to disclose, and silently
			// showing a code entry form for mail that never left is cruel.
			render("code", address,
				"We could not send that code. Check the address, or try again shortly.")
			return
		}
		render("code", address, "")
	}
}

var emailOTPPage = template.Must(template.New("emailotp").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email sign-in codes</title><style>` + pageCSS + `</style></head>
<body>
{{if eq .Stage "done"}}
<h1>Email codes are on</h1>
<p>You will be asked for a code from this address when you sign in.</p>
<p class="hint">This is the weakest of the second factors we offer, because
account recovery already goes to your email &mdash; anybody with your mailbox can
do both. An authenticator app or a passkey is stronger, and you can add one at
any time.</p>
{{else if eq .Stage "code"}}
<h1>Check your email</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<p>We sent a code to <strong>{{.Address}}</strong>.</p>
<form method="POST" action="/account/mfa/email">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<input type="hidden" name="step" value="verify">
<input type="hidden" name="address" value="{{.Address}}">
<label for="c">Code</label>
<input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
<button type="submit">Confirm</button>
</form>
{{else}}
<h1>Email sign-in codes</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<p>We will send a code to this address each time you sign in.</p>
<form method="POST" action="/account/mfa/email">
<input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
<label for="a">Email address</label>
<input id="a" name="address" type="email" value="{{.Address}}" autofocus required>
<button type="submit">Send a code</button>
</form>
<p class="hint">An authenticator app is stronger: your email is also how your
account is recovered, so a code sent there protects you from a stolen password
but not from a stolen mailbox.</p>
{{end}}
</body></html>`))

// handleSMSOTPEnrol turns on a text message as a second factor.
//
// Two steps, and the second is not optional: a number is enrolled, a code is
// sent to it, and the factor counts only once that code comes back. Enrolling
// and trusting in one step means a typo puts a stranger's phone between a
// person and their own account -- and they find out at the worst moment, when
// they are already locked out.
func (s *Server) handleSMSOTPEnrol(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, userID, orgID, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, parkLogin("/account/mfa/sms"), http.StatusSeeOther)
		return
	}

	csrf, err := s.csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	render := func(stage, number, msg string) {
		s.renderPage(w, r, smsOTPPage, map[string]any{
			"Stage": stage, "Number": number, "Error": msg,
			"CSRF": csrf, "CSRFField": csrfFormField,
			"Configured": s.texter != nil,
		})
	}

	if r.Method == http.MethodGet {
		cred, lerr := store.LoadSMSOTP(ctx, s.db, userID)
		switch {
		case lerr == nil && cred.Verified:
			render("enrolled", sms.RedactNumber(cred.Number), "")
		case lerr == nil:
			// Enrolled but never proven. Resume where they left off rather than
			// starting again: the number is already stored and re-typing it is
			// another chance to mistype it.
			render("verify", sms.RedactNumber(cred.Number), "")
		default:
			render("start", "", "")
		}
		return
	}

	if err := r.ParseForm(); err != nil || !checkCSRF(r) {
		render("start", "", "That form expired. Try again.")
		return
	}

	// Refused up front when no gateway is configured. Accepting an enrolment
	// that can never deliver a code would be building somebody a lockout.
	if s.texter == nil {
		render("start", "",
			"Text messages are not available on this server. Ask an administrator, "+
				"or use an authenticator app instead.")
		return
	}

	switch r.PostForm.Get("step") {
	case "verify":
		tx, terr := s.db.Begin(ctx)
		if terr != nil {
			render("verify", "", "Something went wrong. Try again.")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		okCode, verr := store.VerifySMSOTP(ctx, tx, userID,
			strings.TrimSpace(r.PostForm.Get("code")))
		if verr != nil {
			s.log.Error("verifying an SMS enrolment code", "err", verr)
			render("verify", "", "Something went wrong. Try again.")
			return
		}
		if !okCode {
			render("verify", "", "That code is not right, or it has expired.")
			return
		}
		if merr := store.MarkSMSOTPVerified(ctx, tx, userID); merr != nil {
			s.log.Error("marking the SMS factor verified", "err", merr)
			render("verify", "", "Something went wrong. Try again.")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "mfa.sms_enrolled", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
		}); aerr != nil {
			s.log.Error("recording the SMS enrolment", "err", aerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			render("verify", "", "Something went wrong. Try again.")
			return
		}
		cred, _ := store.LoadSMSOTP(ctx, s.db, userID)
		number := ""
		if cred != nil {
			number = sms.RedactNumber(cred.Number)
		}
		render("enrolled", number, "")

	case "remove":
		tx, terr := s.db.Begin(ctx)
		if terr != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if rerr := store.RemoveSMSOTP(ctx, tx, userID); rerr != nil {
			s.log.Error("removing the SMS factor", "err", rerr)
			render("start", "", "Something went wrong. Try again.")
			return
		}
		if aerr := audit.Write(ctx, tx, audit.Event{
			Type: "mfa.sms_removed", OrgID: orgID, SubjectID: userID,
			CorrelationID: correlationID(ctx),
		}); aerr != nil {
			s.log.Error("recording the SMS removal", "err", aerr)
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}
		render("start", "", "")

	default: // "send"
		tx, terr := s.db.Begin(ctx)
		if terr != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		number, nerr := store.EnrollSMSOTP(ctx, tx, userID, orgID,
			r.PostForm.Get("number"))
		if nerr != nil {
			// The number errors are written for the person typing them and are
			// shown as-is: "give the number in international form" is actionable
			// and reveals nothing.
			render("start", r.PostForm.Get("number"), nerr.Error())
			return
		}

		code, to, ierr := store.IssueSMSOTP(ctx, tx, userID)
		switch {
		case errors.Is(ierr, store.ErrSMSOTPTooSoon):
			// A live code is already on its way. Moving to the verify step is
			// the right answer -- they have one.
			render("verify", sms.RedactNumber(number), "")
			return
		case ierr != nil:
			s.log.Error("issuing an SMS enrolment code", "err", ierr)
			render("start", "", "Something went wrong. Try again.")
			return
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			render("start", "", "Something went wrong. Try again.")
			return
		}

		if serr := s.texter.Send(ctx, sms.Message{
			To: to,
			Body: fmt.Sprintf("%s: your verification code is %s. It expires in %d minutes.",
				s.cfg.Issuer, code, int(store.SMSOTPLifetime.Minutes())),
		}); serr != nil {
			// Surfaced, unlike a sign-in send. Here the person is setting the
			// factor up and can fix a wrong number; telling them nothing would
			// leave them waiting for a message that is never coming.
			s.log.Error("sending an SMS enrolment code", "err", serr,
				"to", sms.RedactNumber(to))
			render("start", number,
				"That message could not be sent. Check the number and try again.")
			return
		}
		render("verify", sms.RedactNumber(number), "")
	}
}

var smsOTPPage = template.Must(template.New("smsotp").Parse(`<!doctype html>
<meta charset="utf-8"><title>Text message codes</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + pageCSS + `</style>
<h1>Text message codes</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}

{{if eq .Stage "enrolled"}}
  <p>Codes are sent to <strong>{{.Number}}</strong>.</p>
  <p class="note">A text message is the weakest second factor available here:
  moving a phone number to a new SIM needs no technical attack, only a
  convincing phone call to a mobile operator. An authenticator app or a passkey
  is stronger, and you can have both.</p>
  <form method="post">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
    <input type="hidden" name="step" value="remove">
    <button type="submit">Remove this factor</button>
  </form>

{{else if eq .Stage "verify"}}
  <p>A code was sent to <strong>{{.Number}}</strong>. Enter it to finish.</p>
  <p class="note">This factor is not active until the code comes back. That is
  what proves the number is yours and not a typo.</p>
  <form method="post">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
    <input type="hidden" name="step" value="verify">
    <label for="code">Code</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
           pattern="[0-9]*" autofocus required>
    <button type="submit">Confirm</button>
  </form>

{{else}}
  {{if .Configured}}
  <form method="post">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRF}}">
    <input type="hidden" name="step" value="send">
    <label for="number">Mobile number, with the country code</label>
    <input id="number" name="number" type="tel" value="{{.Number}}"
           placeholder="+44 7700 900123" autocomplete="tel" autofocus required>
    <button type="submit">Send a code</button>
  </form>
  <p class="note">Start with a + and the country code. Without it the number
  cannot be dialled, and guessing wrong sends your codes to somebody else.</p>
  {{else}}
  <p class="note">Text messages are not available on this server.</p>
  {{end}}
{{end}}
<p class="note"><a href="/account">Back to your account</a></p>
`))
