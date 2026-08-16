// Package duo integrates Duo's Universal Prompt as a second factor.
//
// Duo speaks an OIDC-shaped flow with three differences that matter, and the
// last one is where integrations go wrong:
//
//  1. Everything is signed with HS512 using the integration's secret key,
//     rather than with a public key from a JWKS. There is no key discovery and
//     no rotation to follow.
//  2. The authorization request is itself a signed JWT in a `request`
//     parameter, so the parameters cannot be edited in the browser.
//  3. The id_token names the user Duo authenticated -- and NOTHING makes that
//     the user we asked about unless we check.
//
// # The bug this package exists to not have
//
// A second factor is a statement about a specific person. Duo returns an
// id_token whose `preferred_username` is who Duo actually challenged; an
// integration that verifies the signature, the issuer, the audience and the
// expiry, and then simply treats the response as "MFA passed", will accept a
// successful Duo authentication of somebody ELSE as proof for the account being
// signed into.
//
// That is not hypothetical: it is the failure Duo's own documentation warns
// about, and the check is one line that every rushed integration omits. Here it
// is in VerifyIDToken, it is not optional, and the test for it is the first one
// in the file.
package duo

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MinStateLength is Duo's own floor. Duo refuses a shorter one, and the
	// reason is worth keeping: state is what ties the response to the browser
	// that started the flow.
	MinStateLength = 22
	// MaxStateLength is Duo's ceiling.
	MaxStateLength = 1024

	// AssertionLifetime bounds a client assertion. Short: it is presented
	// immediately, and a five-minute window is five minutes in which a captured
	// assertion is a working credential for the integration.
	AssertionLifetime = 5 * time.Minute
)

// Config is one Duo application integration.
type Config struct {
	// ClientID is Duo's integration key (ikey), 20 characters.
	ClientID string
	// ClientSecret is the secret key (skey), 40 characters. It signs every
	// assertion and verifies every id_token: it is the whole security of this
	// integration.
	ClientSecret string
	// APIHost is api-XXXXXXXX.duosecurity.com, without a scheme.
	APIHost string
	// RedirectURI is where Duo sends the browser back. Registered with Duo and
	// matched exactly.
	RedirectURI string

	// FailOpen decides what happens when Duo is UNREACHABLE.
	//
	// Off by default, and that default is a real choice with a real cost: if
	// Duo is down, nobody with Duo enrolled can sign in. Failing open is the
	// other side of the same coin -- an attacker who can take Duo off the
	// network for one victim has removed their second factor entirely, and
	// blocking one host's outbound traffic is not a high bar.
	//
	// Duo's own SDKs offer both. Naming it FailOpen rather than something
	// softer means nobody turns it on without reading the word.
	FailOpen bool

	// HTTP is overridden in tests.
	HTTP *http.Client

	// testBase points the client at a local server instead of Duo.
	//
	// Unexported, and set only by SetInsecureBaseURL, which refuses unless the
	// deployment has already declared itself insecure. Validate rejects any host
	// that is not Duo's precisely because every call carries a signed assertion
	// naming this integration, and a freely settable base URL would be a way to
	// hand that to somebody else.
	testBase string
}

// SetInsecureBaseURL points this integration at a local Duo stand-in.
//
// For local development and end-to-end tests only, and it refuses unless the
// caller passes allowInsecure -- which the engine only does when the deployment
// has already set SIGNARI_INSECURE_ISSUER, i.e. has already said it is not
// production. Without that gate this would be a supported way to redirect the
// second factor to a server of somebody else's choosing.
func (c *Config) SetInsecureBaseURL(base string, allowInsecure bool) error {
	if !allowInsecure {
		return fmt.Errorf("a Duo base URL override is only available on a deployment " +
			"that has already allowed an insecure issuer; on a real deployment it " +
			"would be a way to point the second factor at another server")
	}
	c.testBase = strings.TrimSuffix(base, "/")
	return nil
}

func (c *Config) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *Config) baseURL() string {
	if c.testBase != "" {
		return c.testBase
	}
	// The host is stored without a scheme, as Duo's console displays it. Adding
	// it here rather than at configuration keeps a stored value that cannot
	// accidentally be http://.
	return "https://" + strings.TrimSuffix(c.APIHost, "/")
}

// Validate checks a configuration before it can be stored.
func (c *Config) Validate() error {
	switch {
	case len(c.ClientID) != 20:
		return fmt.Errorf("the Duo client ID (integration key) is 20 characters, got %d",
			len(c.ClientID))
	case len(c.ClientSecret) != 40:
		return fmt.Errorf("the Duo client secret (secret key) is 40 characters, got %d",
			len(c.ClientSecret))
	case c.APIHost == "":
		return fmt.Errorf("the Duo API host is required (api-XXXXXXXX.duosecurity.com)")
	case strings.Contains(c.APIHost, "://"):
		return fmt.Errorf("give the Duo API host without a scheme, e.g. "+
			"api-1234abcd.duosecurity.com (got %q)", c.APIHost)
	case !strings.HasSuffix(c.APIHost, ".duosecurity.com") &&
		!strings.HasSuffix(c.APIHost, ".duofederal.com"):
		// Refused rather than allowed with a warning. This host receives a
		// signed assertion carrying the integration's identity on every check;
		// pointing it somewhere else hands that to whoever runs it.
		return fmt.Errorf("the Duo API host must be a duosecurity.com or "+
			"duofederal.com address (got %q)", c.APIHost)
	case c.RedirectURI == "":
		return fmt.Errorf("the Duo redirect URI is required and must match the one " +
			"registered in the Duo admin panel exactly")
	}
	return nil
}

// NewState returns a random value long enough for Duo to accept.
func NewState() (string, error) {
	b := make([]byte, 24) // 32 base64url characters, comfortably over the floor
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HealthCheck asks whether Duo can serve a prompt right now.
//
// Called BEFORE redirecting a browser. Without it, a Duo outage sends the user
// to a page that will not load and leaves them with a half-finished sign-in and
// no explanation -- and, worse, leaves the deployment unable to apply its own
// fail-open decision, because by then the browser has already left.
func (c *Config) HealthCheck(ctx context.Context) error {
	assertion, err := c.clientAssertion(c.baseURL() + "/oauth/v1/health_check")
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL()+"/oauth/v1/health_check", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("reaching Duo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var out struct {
		Stat          string `json:"stat"`
		Message       string `json:"message"`
		MessageDetail string `json:"message_detail"`
		Code          int    `json:"code"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("Duo answered something that is not JSON (HTTP %d)", resp.StatusCode)
	}
	if out.Stat != "OK" {
		// The detail is the part with a fix attached: a wrong secret key and an
		// expired integration produce different messages and different actions.
		detail := out.Message
		if out.MessageDetail != "" {
			detail += ": " + out.MessageDetail
		}
		return fmt.Errorf("Duo refused the health check: %s (code %d)", detail, out.Code)
	}
	return nil
}

// AuthorizeURL builds the URL to send the browser to.
//
// username is the person being authenticated, and it is carried INSIDE the
// signed request JWT. The whole point is that it cannot be edited between here
// and Duo -- and VerifyIDToken then checks that the answer names the same
// person.
func (c *Config) AuthorizeURL(state, username string) (string, error) {
	if len(state) < MinStateLength || len(state) > MaxStateLength {
		return "", fmt.Errorf("the state must be %d to %d characters (got %d)",
			MinStateLength, MaxStateLength, len(state))
	}
	if username == "" {
		return "", fmt.Errorf("no username: a Duo prompt has to be about somebody, " +
			"and an empty one would let Duo choose")
	}

	now := time.Now()
	claims := map[string]any{
		"response_type":          "code",
		"scope":                  "openid",
		"exp":                    now.Add(AssertionLifetime).Unix(),
		"client_id":              c.ClientID,
		"redirect_uri":           c.RedirectURI,
		"state":                  state,
		"duo_uname":              username,
		"iss":                    c.ClientID,
		"aud":                    c.baseURL(),
		"use_duo_code_attribute": true,
	}
	request, err := signHS512(claims, c.ClientSecret)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("request", request)
	return c.baseURL() + "/oauth/v1/authorize?" + q.Encode(), nil
}

// Result is what Duo said about the authentication.
type Result struct {
	// Username is Duo's preferred_username: WHO Duo actually challenged.
	Username string
	// AuthTime is when the challenge was answered.
	AuthTime time.Time
	// Factor and Device describe what was used, for the audit trail.
	Factor string
	Device string
}

// Exchange redeems the code and verifies the id_token.
//
// expectedUsername is the account being signed into HERE. It is compared with
// the username inside the id_token, and a mismatch is refused -- see the
// package comment.
func (c *Config) Exchange(ctx context.Context, code, expectedUsername string) (*Result, error) {
	if code == "" {
		return nil, fmt.Errorf("no authorization code")
	}
	tokenURL := c.baseURL() + "/oauth/v1/token"

	assertion, err := c.clientAssertion(tokenURL)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("client_assertion_type",
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Duo requires a User-Agent and rejects requests without one.
	req.Header.Set("User-Agent", "signari-duo/1")

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging the Duo code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Duo refused the exchange: %s", duoError(resp.StatusCode, body))
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return nil, fmt.Errorf("Duo returned no id_token")
	}
	return c.VerifyIDToken(tok.IDToken, expectedUsername, time.Now())
}

// VerifyIDToken checks every claim that makes the token mean something.
func (c *Config) VerifyIDToken(raw, expectedUsername string, now time.Time) (*Result, error) {
	claims, err := verifyHS512(raw, c.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Issuer: Duo's token endpoint for THIS API host. A token minted by another
	// Duo tenant is a valid Duo token and is not ours.
	iss, _ := claims["iss"].(string)
	if want := c.baseURL() + "/oauth/v1/token"; iss != want {
		return nil, fmt.Errorf("the Duo token was issued by %q, not %q", iss, want)
	}

	// Audience: this integration.
	if !audienceContains(claims["aud"], c.ClientID) {
		return nil, fmt.Errorf("the Duo token is addressed to %v, not to this "+
			"integration", claims["aud"])
	}

	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, fmt.Errorf("the Duo token has no expiry, so a copy of it would " +
			"be a permanent proof of a second factor")
	}
	if now.After(exp) {
		return nil, fmt.Errorf("the Duo token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if iat, ok := numericDate(claims["iat"]); ok && now.Add(time.Minute).Before(iat) {
		return nil, fmt.Errorf("the Duo token is dated in the future")
	}

	// THE check. Duo authenticated somebody; this is where we find out whether
	// it was the person signing in here.
	username, _ := claims["preferred_username"].(string)
	if username == "" {
		return nil, fmt.Errorf("the Duo token names no user, so it proves nothing " +
			"about the account being signed into")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(username)),
		[]byte(strings.ToLower(expectedUsername))) != 1 {
		return nil, fmt.Errorf("Duo authenticated %q, but the account being signed "+
			"into is %q. A second factor proved for one person is not a second "+
			"factor for another", username, expectedUsername)
	}

	res := &Result{Username: username}
	if t, ok := numericDate(claims["auth_time"]); ok {
		res.AuthTime = t
	}
	// auth_result carries what was used, when Duo is configured to send it.
	if ar, ok := claims["auth_result"].(map[string]any); ok {
		if s, ok := ar["status"].(string); ok && !strings.EqualFold(s, "allow") {
			reason, _ := ar["status_msg"].(string)
			return nil, fmt.Errorf("Duo did not allow the authentication: %s (%s)", s, reason)
		}
	}
	if ctx, ok := claims["auth_context"].(map[string]any); ok {
		res.Factor, _ = ctx["factor"].(string)
		if d, ok := ctx["access_device"].(map[string]any); ok {
			res.Device, _ = d["hostname"].(string)
		}
	}
	return res, nil
}

// clientAssertion builds the JWT that authenticates this integration.
func (c *Config) clientAssertion(audience string) (string, error) {
	jti, err := NewState()
	if err != nil {
		return "", err
	}
	now := time.Now()
	return signHS512(map[string]any{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": audience,
		"exp": now.Add(AssertionLifetime).Unix(),
		"iat": now.Unix(),
		"jti": jti,
	}, c.ClientSecret)
}

func duoError(status int, body []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err == nil {
		switch {
		case e.Description != "":
			return e.Error + ": " + e.Description
		case e.Error != "":
			return e.Error
		case e.Message != "":
			return e.Message
		}
	}
	return fmt.Sprintf("HTTP %d", status)
}

// signHS512 produces a compact JWS.
//
// Written here rather than pulled in as a dependency: it is thirty lines, and a
// JWT library in the authentication path is a supply chain in the
// authentication path.
func signHS512(claims map[string]any, secret string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS512", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyHS512 checks the signature and returns the claims.
//
// The algorithm is FIXED at HS512, not read from the header. Reading it is the
// alg-confusion family of bugs: a token declaring "none" verifies trivially,
// and one declaring an asymmetric algorithm can be verified with a public key
// as if it were an HMAC secret.
func verifyHS512(raw, secret string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("the Duo token is not a JWS")
	}

	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("the Duo token header is not base64url")
	}
	if err := json.Unmarshal(h, &hdr); err != nil {
		return nil, fmt.Errorf("the Duo token header is not JSON")
	}
	if hdr.Alg != "HS512" {
		// Refused, not accommodated. Duo signs with HS512; anything else is
		// either a different product or an attacker choosing the algorithm.
		return nil, fmt.Errorf("the Duo token is signed with %q, and only HS512 is "+
			"accepted", hdr.Alg)
	}

	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("the Duo token signature is not base64url")
	}
	if !hmac.Equal(got, want) {
		return nil, fmt.Errorf("the Duo token signature does not verify")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("the Duo token payload is not base64url")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the Duo token payload is not JSON")
	}
	return claims, nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}
