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
	"regexp"
	"strings"
)

// signIn takes a person from the authorization endpoint to redeemed tokens the
// way a browser does: follow the provider's redirects, fill in the login form,
// allow the consent form if there is one, and redeem the code with its PKCE
// verifier. The forms are Signari's (login.html, consent.html): a hidden-field
// form posting `username` and `password`, and one posting `decision=allow`.
func signIn(ctx context.Context, hc *http.Client, e *env) (tokenResponse, error) {
	c := e.cfg
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

	// A sign-in is a handful of hops; a loop of them is a misconfiguration.
	for hop := 0; hop < 10; hop++ {
		resp, err := hc.Do(next)
		if err != nil {
			return tokenResponse{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

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
			action, fields, ok := parseForm(string(body))
			if !ok {
				return tokenResponse{}, fmt.Errorf("a page at %s with no form to submit", next.URL.Path)
			}
			if _, isLogin := fields["username"]; isLogin {
				fields.Set("username", c.Username)
				fields.Set("password", c.Password)
			}
			if fields.Has("decision") {
				fields.Set("decision", "allow")
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
			return tokenResponse{}, fmt.Errorf("%s answered %d: %s", next.URL.Path, resp.StatusCode, trim(body))
		}
	}
	return tokenResponse{}, fmt.Errorf("no authorization code after ten hops")
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
