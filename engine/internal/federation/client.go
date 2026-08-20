package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Config is one configured external provider.
type Config struct {
	ID           string
	OrgID        string
	Slug         string
	DisplayName  string
	Kind         Kind
	ClientID     string
	ClientSecret string
	Preset       Preset
	Policy       Policy
	// Endpoint overrides for the generic OIDC kind. Named with an Override
	// suffix so they cannot collide with the methods that resolve them --
	// a field and a method of the same name is a compile error, and naming them
	// alike is how the resolution gets bypassed by accident.
	AuthorizeOverride, TokenOverride, UserinfoOverride string
	JWKSOverride, IssuerOverride                       string
	Scopes                                             []string
}

func (c Config) authorizeURL() string { return pick(c.AuthorizeOverride, c.Preset.AuthorizeURL) }
func (c Config) tokenURL() string     { return pick(c.TokenOverride, c.Preset.TokenURL) }
func (c Config) userinfoURL() string  { return pick(c.UserinfoOverride, c.Preset.UserinfoURL) }
func (c Config) jwksURL() string      { return pick(c.JWKSOverride, c.Preset.JWKSURL) }
func (c Config) issuer() string       { return pick(c.IssuerOverride, c.Preset.Issuer) }

// emailsURL is GitHub's separate verified-address endpoint. Derived from the
// userinfo URL when the preset does not name one, so a GitHub Enterprise host
// works without a second setting.
func (c Config) emailsURL() string {
	if c.Preset.EmailsURL != "" && c.UserinfoOverride == "" {
		return c.Preset.EmailsURL
	}
	return strings.TrimSuffix(c.userinfoURL(), "/") + "/emails"
}

func (c Config) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return c.Preset.Scopes
}

func pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// AuthorizeURL builds the URL to send the browser to.
//
// PKCE is used even where the provider is a confidential client and does not
// require it. The code arrives back on a redirect the browser can see, and
// PKCE is what stops a code intercepted there being exchanged by anybody else.
// It costs one hash.
func (c Config) AuthorizeURL(redirectURI, state, nonce, verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(c.scopes(), " ")},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if c.Preset.OIDC {
		// Binds the id_token to this flow. Without it an id_token obtained
		// elsewhere can be replayed into this login.
		q.Set("nonce", nonce)
	}
	if c.Kind == KindMicrosoft {
		// Without this Microsoft may return a token for a different tenant's
		// account silently; being explicit keeps the endpoint predictable.
		q.Set("response_mode", "query")
	}
	sep := "?"
	if strings.Contains(c.authorizeURL(), "?") {
		sep = "&"
	}
	return c.authorizeURL() + sep + q.Encode()
}

// TokenSet is what the provider returned from the token endpoint.
type TokenSet struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// ExchangeCode swaps the authorization code for tokens.
func (c Config) ExchangeCode(ctx context.Context, hc *http.Client, redirectURI, code, verifier string) (*TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {c.ClientID},
		"code_verifier": {verifier},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// GitHub returns form-encoded unless asked otherwise, and silently: you get
	// a 200 with a body that json.Unmarshal turns into an empty struct.
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling the provider's token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the provider's token endpoint answered %d: %s",
			resp.StatusCode, truncate(string(body), 200))
	}
	var ts TokenSet
	if err := json.Unmarshal(body, &ts); err != nil {
		return nil, fmt.Errorf("the provider's token response did not parse: %w", err)
	}
	if ts.AccessToken == "" && ts.IDToken == "" {
		// Covers GitHub's error shape, which is a 200 with an `error` field.
		return nil, fmt.Errorf("the provider returned no token: %s", truncate(string(body), 200))
	}
	return &ts, nil
}

// FetchIdentity turns a token set into an external identity.
func (c Config) FetchIdentity(ctx context.Context, hc *http.Client, ts *TokenSet, nonce string) (ExternalIdentity, error) {
	if c.Kind == KindGitHub {
		return c.githubIdentity(ctx, hc, ts)
	}
	if c.Preset.OIDC && ts.IDToken != "" {
		return c.oidcIdentity(ctx, hc, ts, nonce)
	}
	return ExternalIdentity{}, fmt.Errorf("the provider returned no id_token and this " +
		"kind has no other way to establish identity")
}

// oidcIdentity verifies the id_token and reads the identity from it.
func (c Config) oidcIdentity(ctx context.Context, hc *http.Client, ts *TokenSet, nonce string) (ExternalIdentity, error) {
	claims, err := c.verifyIDToken(ctx, hc, ts.IDToken, nonce)
	if err != nil {
		return ExternalIdentity{}, err
	}

	id := ExternalIdentity{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}

	switch c.Kind {
	case KindMicrosoft:
		// Microsoft's own documentation: the email claim "isn't guaranteed to be
		// correct... never use it for authorization". The optional xms_edov claim
		// is the only signal that the domain owner was verified, and it has to be
		// added to the app registration to appear at all.
		id.EmailVerified = claims.XMSEdov != nil && *claims.XMSEdov
	default:
		id.EmailVerified = claims.EmailVerified
	}
	return id, nil
}

// idTokenClaims is only what we read. Anything not listed cannot be trusted by
// accident.
type idTokenClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Expiry   int64           `json:"exp"`
	IssuedAt int64           `json:"iat"`
	// NotBefore is the other half of the validity span. ASVS 5.0.0 V9.2.1: "if a
	// validity time span is present in the token data, the token and its content
	// are accepted only if the verification time is within this validity time
	// span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified."
	//
	// We never emit nbf ourselves, which is why it was missing here: every token
	// this code was written against lacked one. An UPSTREAM may emit it, and a
	// provider that says "not valid before T" has said something we were ignoring.
	NotBefore     int64  `json:"nbf"`
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	// XMSEdov is a pointer so "absent" and "false" stay distinguishable --
	// absent means the app registration never asked for it, which is an
	// operator problem with a different fix from "the domain is unverified".
	XMSEdov *bool `json:"xms_edov"`
}

// verifyIDToken checks the signature and every binding claim.
//
// Written out rather than delegated, because the failure mode of a
// half-verified id_token is silent: it parses, the claims look right, and the
// only thing missing is any reason to believe them.
func (c Config) verifyIDToken(ctx context.Context, hc *http.Client, raw, nonce string) (*idTokenClaims, error) {
	jwks, err := c.fetchJWKS(ctx, hc)
	if err != nil {
		return nil, err
	}

	// Algorithms are allow-listed. Passing the token's own header algorithm to
	// the parser is how "alg: none" and HMAC-with-the-public-key confusion get
	// in -- the attacker chooses the algorithm.
	sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.PS256,
	})
	if err != nil {
		return nil, fmt.Errorf("the id_token did not parse: %w", err)
	}

	var payload []byte
	var lastErr error
	for _, key := range jwks.Keys {
		if p, err := sig.Verify(key); err == nil {
			payload = p
			break
		} else {
			lastErr = err
		}
	}
	if payload == nil {
		return nil, fmt.Errorf("the id_token signature did not verify against any key in "+
			"the provider's JWKS: %w", lastErr)
	}

	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the id_token claims did not parse: %w", err)
	}

	if want := c.issuer(); want != "" && claims.Issuer != want {
		// Microsoft's issuer is per-tenant, so `common` deployments legitimately
		// vary -- which is why the check is skipped only when no issuer is
		// configured, never silently.
		return nil, fmt.Errorf("the id_token issuer is %q, expected %q", claims.Issuer, want)
	}
	if !audienceContains(claims.Audience, c.ClientID) {
		return nil, fmt.Errorf("the id_token audience does not contain our client id; " +
			"this token was issued for a different application")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("the id_token carries no subject")
	}
	now := time.Now()
	if claims.Expiry == 0 || now.After(time.Unix(claims.Expiry, 0)) {
		return nil, fmt.Errorf("the id_token has expired")
	}
	// The lower bound of the validity span, when the upstream set one.
	//
	// Skew is allowed in the same direction and by the same amount as everywhere
	// else in this codebase: a provider whose clock runs a few seconds fast is a
	// configuration problem, not an attack, and refusing it produces an
	// intermittent login failure nobody can reproduce.
	if claims.NotBefore != 0 &&
		time.Unix(claims.NotBefore, 0).After(now.Add(federationClockSkew)) {
		return nil, fmt.Errorf("the id_token is not valid until %s, which is more "+
			"than %s from now",
			time.Unix(claims.NotBefore, 0).UTC().Format(time.RFC3339), federationClockSkew)
	}
	// And an iat far in the future, which is the same fault reported by a
	// different claim. Checked only when present: iat is REQUIRED by OIDC Core
	// but an upstream that omits it fails elsewhere, and refusing here would
	// name the wrong problem.
	if claims.IssuedAt != 0 &&
		time.Unix(claims.IssuedAt, 0).After(now.Add(federationClockSkew)) {
		return nil, fmt.Errorf("the id_token says it was issued at %s, which is in "+
			"the future by more than %s",
			time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339), federationClockSkew)
	}
	if nonce != "" && claims.Nonce != nonce {
		// The binding to THIS login. Without it an id_token obtained anywhere
		// else for the same client can be replayed into this flow.
		return nil, fmt.Errorf("the id_token nonce does not match this login")
	}
	return &claims, nil
}

func audienceContains(raw json.RawMessage, clientID string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == clientID
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

func (c Config) fetchJWKS(ctx context.Context, hc *http.Client) (*jose.JSONWebKeySet, error) {
	u := c.jwksURL()
	if u == "" {
		return nil, fmt.Errorf("no JWKS URL is configured for this provider, so its " +
			"id_token signature cannot be checked")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching the provider's JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the provider's JWKS endpoint answered %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("the provider's JWKS did not parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("the provider's JWKS is empty")
	}
	return &set, nil
}

// githubIdentity reads identity from GitHub's user API.
//
// GitHub is not OpenID Connect: there is no id_token and nothing is signed.
// That is acceptable because the access token was obtained over TLS directly
// from GitHub and is presented back to GitHub -- but it means none of the
// verification above applies, and the email needs its own request.
func (c Config) githubIdentity(ctx context.Context, hc *http.Client, ts *TokenSet) (ExternalIdentity, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	// The CONFIGURED endpoint, not a hardcoded one. GitHub Enterprise Server
	// lives on the customer's own host, and hardcoding api.github.com makes this
	// both untestable and unusable there.
	if err := githubGet(ctx, hc, ts.AccessToken, c.userinfoURL(), &user); err != nil {
		return ExternalIdentity{}, err
	}
	if user.ID == 0 {
		return ExternalIdentity{}, fmt.Errorf("GitHub returned no user id")
	}

	id := ExternalIdentity{
		// The numeric id, NOT the login. A login can be changed and, once
		// released, claimed by somebody else -- so keying on it means an account
		// here can be inherited by whoever takes the abandoned username.
		Subject: strconv.FormatInt(user.ID, 10),
		Name:    user.Name,
	}
	if id.Name == "" {
		id.Name = user.Login
	}

	// The address from /user is whatever the user set as publicly visible, and
	// may be one they never confirmed. The verified flag lives here instead.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := githubGet(ctx, hc, ts.AccessToken, c.emailsURL(), &emails); err != nil {
		// Without this endpoint we cannot establish verification, so the address
		// is carried unverified rather than assumed good.
		id.Email = user.Email
		id.EmailVerified = false
		return id, nil
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			id.Email = e.Email
			id.EmailVerified = true
			return id, nil
		}
	}
	// No verified primary. Fall back to any verified address before giving up,
	// since plenty of people have a verified secondary and an unverified primary.
	for _, e := range emails {
		if e.Verified {
			id.Email = e.Email
			id.EmailVerified = true
			return id, nil
		}
	}
	id.Email = user.Email
	id.EmailVerified = false
	return id, nil
}

func githubGet(ctx context.Context, hc *http.Client, token, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// federationClockSkew is how far ahead an upstream provider's clock may be.
//
// The same ten seconds clientauth allows, and for the same reason: FAPI 2.0
// §5.3.2.1 requires accepting 0-10 seconds of future-dating and rejecting more
// than 60, and every second of tolerance is a second a token is usable before its
// issuer says it should be.
const federationClockSkew = 10 * time.Second
