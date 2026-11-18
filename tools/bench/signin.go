package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// driver is how one product's own sign-in pages are filled in (E.21): which fields take
// the name, the password and a one-time code, how its consent form is allowed, and where
// its page links to an upstream provider. A browser does nothing cleverer: it fills in
// what the page asks for and follows where the page sends it.
type driver struct {
	user, pass []string // a field of the first list takes the name, of the second the password
	code       string   // the field a TOTP code goes in
	// allow sets a consent form's fields to allow, reporting whether the page was one.
	allow func(url.Values) bool
	// upstream finds, on a sign-in page, the link to the upstream provider named via.
	upstream func(page, via string) (string, bool)
	// flow, when set, replaces the form walk for a product whose pages are a front end to an
	// API that runs the sign-in. It answers where the browser goes next, whether it handled
	// the page, and how long the one request that spent a TOTP code took.
	flow func(ctx context.Context, hc *http.Client, e *env, start *http.Request) (*http.Request, bool, time.Duration, error)
	// enrol and passkey, when set, replace the engine's account-page enrolment and its
	// passkey endpoints with the product's own pages.
	enrol   func(ctx context.Context, hc *http.Client, e *env) (*softPasskey, error)
	passkey func(p *softPasskey, ctx context.Context, hc *http.Client, e *env) error
}

func linkTo(pattern string) func(page, via string) (string, bool) {
	return func(page, via string) (string, bool) {
		m := regexp.MustCompile(`href="(` + strings.ReplaceAll(pattern, "{via}", regexp.QuoteMeta(via)) + `[^"]*)"`).FindStringSubmatch(page)
		if m == nil {
			return "", false
		}
		return html.UnescapeString(m[1]), true
	}
}

// namedLink finds the link whose text names the provider, where the address carries an
// id and not the name: a page that lists each as <a href=...><span>name</span></a>.
func namedLink(prefix string) func(page, via string) (string, bool) {
	return func(page, via string) (string, bool) {
		links := regexp.MustCompile(`(?s)<a href="(` + regexp.QuoteMeta(prefix) + `[^"]*)"[^>]*>(.*?)</a>`)
		for _, m := range links.FindAllStringSubmatch(page, -1) {
			if regexp.MustCompile(`>\s*` + regexp.QuoteMeta(via) + `\s*<`).MatchString(m[2]) {
				return html.UnescapeString(m[1]), true
			}
		}
		return "", false
	}
}

var drivers = map[string]driver{
	// Signari's login.html and consent.html.
	"signari": {user: []string{"username"}, pass: []string{"password"}, code: "code",
		allow: func(f url.Values) bool {
			if !f.Has("decision") {
				return false
			}
			f.Set("decision", "allow")
			return true
		},
		upstream: linkTo(`/login/with/{via}`)},
	// Another provider's driver is a file of its own that adds itself here at init, kept
	// where the product it walks may be named.
}

// traceHop prints a hop of a sign-in to stderr when BENCH_TRACE is set: where it went, what
// came back, and the fields of the form a page held. Writing a driver for a product's pages
// is reading them, and this is how (E.21).
func traceHop(hop int, req *http.Request, resp *http.Response, body []byte) {
	if os.Getenv("BENCH_TRACE") == "" {
		return
	}
	line := fmt.Sprintf("%2d %s %s -> %d %s", hop, req.Method, req.URL.Path, resp.StatusCode, resp.Header.Get("Location"))
	if action, fields, ok := parseForm(string(body)); ok {
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		line += fmt.Sprintf("\n   form %s %v", action, names)
	} else if resp.StatusCode == http.StatusOK {
		line += "\n   " + trim(body)
	}
	fmt.Fprintln(os.Stderr, line)
}

// driverFor is the -driver named, Signari's when none is.
func driverFor(c *config) (driver, error) {
	name := c.Driver
	if name == "" {
		name = "signari"
	}
	d, ok := drivers[name]
	if !ok {
		return driver{}, fmt.Errorf("no sign-in driver %q", c.Driver)
	}
	return d, nil
}

// signIn takes a person from the authorization endpoint to redeemed tokens the
// way a browser does: follow the provider's redirects, fill in the login form,
// allow the consent form if there is one, and redeem the code with its PKCE
// verifier. The forms are the -driver's; Signari's by default (login.html,
// consent.html).
func signIn(ctx context.Context, hc *http.Client, e *env) (tok tokenResponse, err error) {
	c := e.cfg
	d, err := driverFor(c)
	if err != nil {
		return tokenResponse{}, err
	}
	verifier := randomString(32)
	state := randomString(16)
	q := url.Values{
		"client_id": {c.ClientID}, "redirect_uri": {c.RedirectURI}, "response_type": {"code"},
		"scope": {c.Scope}, "state": {state}, "nonce": {randomString(16)},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	next, err := http.NewRequestWithContext(ctx, http.MethodGet, e.md.AuthorizationEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		return tokenResponse{}, err
	}

	// With a TOTP seed the one request measured is the one that spends the code: all
	// the rest of a sign-in is a password hash and a redirect, measured by `signin`.
	started := time.Now()
	var spending bool
	var spent time.Duration
	defer func() {
		tok.spentCode = spent > 0
		if spent > 0 {
			_ = outsideFor(ctx, time.Since(started)-spent)
		}
	}()

	// A sign-in is a handful of hops, more through a provider; a loop of them is a
	// misconfiguration.
	for hop := 0; hop < 16; hop++ {
		sent := time.Now()
		resp, err := hc.Do(next)
		if err != nil {
			return tokenResponse{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if spending {
			spent, spending = time.Since(sent), false
		}
		traceHop(hop, next, resp, body)

		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc, err := next.URL.Parse(resp.Header.Get("Location"))
			if err != nil {
				return tokenResponse{}, err
			}
			if strings.HasPrefix(loc.String(), c.RedirectURI) {
				return redeem(ctx, hc, e, loc.Query(), state, verifier)
			}
			if next, err = http.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil); err != nil {
				return tokenResponse{}, err
			}
		case resp.StatusCode == http.StatusOK:
			if d.flow != nil {
				// A product whose sign-in is an API: its driver takes the request
				// that reached the page and answers where the browser goes next.
				n, done, spentHere, err := d.flow(ctx, hc, e, next)
				if err != nil {
					return tokenResponse{}, err
				}
				spent += spentHere
				if done {
					next = n
					continue
				}
			}
			action, fields, ok := parseForm(string(body))
			if !ok {
				return tokenResponse{}, fmt.Errorf("a page at %s with no form to submit", next.URL.Path)
			}
			userField, passField := firstOf(fields, d.user), firstOf(fields, d.pass)
			if (userField != "" || passField != "") && c.Via != "" && d.upstream != nil {
				// The provider's link on the page, as a person would take it.
				link, found := d.upstream(string(body), c.Via)
				if !found {
					return tokenResponse{}, fmt.Errorf("the sign-in page offers no provider %q", c.Via)
				}
				target, err := next.URL.Parse(link)
				if err != nil {
					return tokenResponse{}, err
				}
				if next, err = http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil); err != nil {
					return tokenResponse{}, err
				}
				continue
			}
			if userField != "" {
				fields.Set(userField, c.Username)
			}
			if passField != "" {
				fields.Set(passField, c.Password)
			}
			d.allow(fields)
			if d.code != "" && fields.Has(d.code) && c.TOTPSeed != "" {
				code, err := totpCode(c.TOTPSeed, time.Now())
				if err != nil {
					return tokenResponse{}, err
				}
				fields.Set(d.code, code)
				spending = true
			}
			target, err := next.URL.Parse(action)
			if err != nil {
				return tokenResponse{}, err
			}
			if next, err = http.NewRequestWithContext(ctx, http.MethodPost, target.String(),
				strings.NewReader(fields.Encode())); err != nil {
				return tokenResponse{}, err
			}
			next.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		default:
			return tokenResponse{}, fmt.Errorf("%s%s answered %d: %s", next.URL.Host, next.URL.Path, resp.StatusCode, trim(body))
		}
	}
	return tokenResponse{}, fmt.Errorf("no authorization code after sixteen hops")
}

func redeem(ctx context.Context, hc *http.Client, e *env, back url.Values, state, verifier string) (tokenResponse, error) {
	if errCode := back.Get("error"); errCode != "" {
		return tokenResponse{}, fmt.Errorf("the authorization was refused: %s %s", errCode, back.Get("error_description"))
	}
	if back.Get("state") != state {
		return tokenResponse{}, fmt.Errorf("the redirect carried another state")
	}
	body, err := postForm(ctx, hc, e.md.TokenEndpoint, e.cfg, url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Get("code")},
		"redirect_uri": {e.cfg.RedirectURI}, "code_verifier": {verifier},
	})
	if err != nil {
		return tokenResponse{}, err
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("no access token in %s", trim(body))
	}
	return tok, nil
}

var (
	formTag  = regexp.MustCompile(`(?is)<form\b[^>]*\baction="([^"]*)"`)
	inputTag = regexp.MustCompile(`(?is)<(?:input|button)\b[^>]*>`)
	attr     = regexp.MustCompile(`(?is)\b(name|value|type)="([^"]*)"`)
)

// parseForm returns a page's first form: its action and the fields a browser
// would submit, hidden ones with their values and visible ones empty. A
// `decision` button is recorded with no value; the caller chooses.
func parseForm(page string) (string, url.Values, bool) {
	m := formTag.FindStringSubmatchIndex(page)
	if m == nil {
		return "", nil, false
	}
	action := html.UnescapeString(page[m[2]:m[3]])
	rest := page[m[1]:]
	if end := strings.Index(strings.ToLower(rest), "</form>"); end >= 0 {
		rest = rest[:end]
	}
	fields := url.Values{}
	for _, tag := range inputTag.FindAllString(rest, -1) {
		var name, value, typ string
		for _, a := range attr.FindAllStringSubmatch(tag, -1) {
			switch strings.ToLower(a[1]) {
			case "name":
				name = html.UnescapeString(a[2])
			case "value":
				value = html.UnescapeString(a[2])
			case "type":
				typ = strings.ToLower(a[2])
			}
		}
		if name == "" {
			continue
		}
		switch {
		case typ == "hidden":
			fields.Add(name, value)
		case strings.HasPrefix(strings.ToLower(tag), "<button"):
			fields.Set(name, "")
		default:
			if !fields.Has(name) {
				fields.Set(name, "")
			}
		}
	}
	return action, fields, true
}

// firstOf is the first of names the form has a field of, "" for none.
func firstOf(fields url.Values, names []string) string {
	for _, n := range names {
		if fields.Has(n) {
			return n
		}
	}
	return ""
}

// pkceChallenge is the S256 code challenge for a verifier (RFC 7636 §4.2).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
