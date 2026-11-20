package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// scenario is one measured operation. worker builds one worker's operation,
// doing whatever setup the operation needs (a token, a bound connection)
// outside the measured window.
type scenario struct {
	help           string
	needsDiscovery bool
	worker         func(context.Context, *env) (func(context.Context) error, error)
}

// discovery is the part of the provider's metadata the scenarios read.
type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	PAREndpoint           string `json:"pushed_authorization_request_endpoint"`
	DeviceEndpoint        string `json:"device_authorization_endpoint"`
	BackchannelEndpoint   string `json:"backchannel_authentication_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type env struct {
	cfg *config
	md  discovery
	// passkey, when set, is what a flow-driven sign-in answers a passkey challenge with
	// (a flow's first stage may offer one beside the name).
	passkey *softPasskey
}

func discoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

func newEnv(ctx context.Context, c *config, needsDiscovery bool) (*env, error) {
	e := &env{cfg: c}
	if !needsDiscovery {
		return e, nil
	}
	if c.Issuer == "" {
		return nil, fmt.Errorf("give -issuer")
	}
	body, err := get(ctx, httpClient(c), discoveryURL(c.Issuer), "")
	if err != nil {
		return nil, fmt.Errorf("reading discovery: %w", err)
	}
	if err := json.Unmarshal(body, &e.md); err != nil {
		return nil, fmt.Errorf("discovery is not JSON: %w", err)
	}
	return e, nil
}

var scenarios = map[string]scenario{
	"discovery": {
		help: "GET the OpenID Connect discovery document", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				_, err := get(ctx, hc, discoveryURL(e.cfg.Issuer), "")
				return err
			}, nil
		},
	},
	"jwks": {
		help: "GET the signing key set", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				_, err := get(ctx, hc, e.md.JWKSURI, "")
				return err
			}, nil
		},
	},
	"client-credentials": {
		help: "issue an access token by the client credentials grant (RFC 6749 §4.4)", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				_, err := clientCredentials(ctx, hc, e)
				return err
			}, nil
		},
	},
	"introspect": {
		help: "introspect one access token (RFC 7662), the token issued outside the window", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			var tok tokenResponse
			var err error
			if e.cfg.IntrospectPerson {
				// A person's access token, from one sign-in per worker: what a resource
				// server is handed, and what a provider that keeps no session for a
				// client's own token can still answer for.
				tok, err = signIn(ctx, hc, asNextPerson(e))
			} else {
				tok, err = clientCredentials(ctx, hc, e)
			}
			if err != nil {
				return nil, err
			}
			endpoint, as := e.md.IntrospectionEndpoint, e.cfg
			if e.cfg.IntrospectURL != "" {
				endpoint = e.cfg.IntrospectURL
			}
			if e.cfg.IntrospectClientID != "" {
				other := *e.cfg
				other.ClientID, other.ClientSecret = e.cfg.IntrospectClientID, e.cfg.IntrospectClientSecret
				as = &other
			}
			if endpoint == "" {
				return nil, fmt.Errorf("the provider advertises no introspection endpoint; -introspect-url names one")
			}
			return func(ctx context.Context) error {
				body, err := postForm(ctx, hc, endpoint, as, url.Values{"token": {tok.AccessToken}})
				if err != nil {
					return err
				}
				var out struct {
					Active bool `json:"active"`
				}
				if err := json.Unmarshal(body, &out); err != nil || !out.Active {
					return fmt.Errorf("introspection did not say active: %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"revoke": {
		help: "issue an access token and revoke it (RFC 7009): the pair, since a token revokes once", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.md.RevocationEndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no revocation endpoint")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				tok, err := clientCredentials(ctx, hc, e)
				if err != nil {
					return err
				}
				_, err = postForm(ctx, hc, e.md.RevocationEndpoint, e.cfg, url.Values{"token": {tok.AccessToken}})
				return err
			}, nil
		},
	},
	"par": {
		help: "push an authorization request (RFC 9126), which the client names and nothing redeems", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.md.PAREndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no pushed authorization endpoint")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				body, err := postForm(ctx, hc, e.md.PAREndpoint, e.cfg, url.Values{"response_type": {"code"},
					"redirect_uri": {e.cfg.RedirectURI}, "scope": {"openid"}, "state": {"bench"},
					"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
					"code_challenge_method": {"S256"}})
				if err != nil {
					return err
				}
				var out struct {
					RequestURI string `json:"request_uri"`
				}
				if err := json.Unmarshal(body, &out); err != nil || out.RequestURI == "" {
					return fmt.Errorf("no request_uri came back: %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"device-start": {
		help: "start a device authorization (RFC 8628), which nobody approves", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.md.DeviceEndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no device authorization endpoint")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				_, err := startDevice(ctx, hc, e)
				return err
			}, nil
		},
	},
	"device-poll": {
		help: "poll for a device authorization nobody has approved, which is what a waiting fleet does", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			if e.md.DeviceEndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no device authorization endpoint")
			}
			hc := httpClient(e.cfg)
			code, err := startDevice(ctx, hc, e)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				status, body, err := postFormStatus(ctx, hc, e.md.TokenEndpoint, e.cfg, url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {code},
				})
				if err != nil {
					return err
				}
				var out struct {
					Error string `json:"error"`
				}
				// RFC 8628 §3.5: waiting is an error response, and these are the two
				// a client polling an unapproved code is meant to get.
				if json.Unmarshal(body, &out) != nil || status != http.StatusBadRequest ||
					(out.Error != "authorization_pending" && out.Error != "slow_down") {
					return fmt.Errorf("the poll answered %d: %s", status, trim(body))
				}
				return nil
			}, nil
		},
	},
	"ciba-start": {
		help: "ask for a person's approval over the back channel (CIBA), taking turns through -people", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.md.BackchannelEndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no backchannel authentication endpoint")
			}
			if e.cfg.People < 1 {
				return nil, fmt.Errorf("give -people: a provider limits the prompts in front of one person")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				n := int(nextPerson.Add(1))%e.cfg.People + 1
				body, err := postForm(ctx, hc, e.md.BackchannelEndpoint, e.cfg, url.Values{"scope": {"openid"},
					"login_hint": {personName(e.cfg, n)}})
				if err != nil {
					return err
				}
				var out struct {
					ID string `json:"auth_req_id"`
				}
				if err := json.Unmarshal(body, &out); err != nil || out.ID == "" {
					return fmt.Errorf("no auth_req_id came back: %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"jwt-bearer": {
		help: "trade an assertion for a token (RFC 7523 §2.1), each with a jti of its own", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			key, err := readSigningKey(e.cfg.AssertionKey)
			if err != nil {
				return nil, fmt.Errorf("-assertion-key: %w", err)
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				now := time.Now()
				kid := e.cfg.AssertionKID
				if kid == "" {
					kid = signingKID
				}
				// The issuer names the authorization server (RFC 7523 §3); one provider
				// accepts only its token endpoint's URL, which §3 says MAY be used.
				audience := e.cfg.AssertionAudience
				if audience == "" {
					audience = e.cfg.Issuer
				}
				assertion, err := signES256As(key, kid, map[string]any{
					"iss": e.cfg.AssertionIssuer, "sub": e.cfg.AssertionSubject, "aud": audience,
					"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": randomString(16),
				})
				if err != nil {
					return err
				}
				form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
				if e.cfg.CCScope != "" {
					form.Set("scope", e.cfg.CCScope)
				}
				body, err := postForm(ctx, hc, e.md.TokenEndpoint, e.cfg, form)
				if err != nil {
					return err
				}
				var tok tokenResponse
				if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
					return fmt.Errorf("no access token in %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"federated": {
		help: "sign in through an upstream OpenID provider, -via naming it, with no session to start from", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.Via == "" {
				return nil, fmt.Errorf("give -via, the slug of the upstream provider")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				// A browser of its own each time, on the same connections, or the second
				// sign-in finds the first's session and never leaves the engine.
				jar, err := cookiejar.New(nil)
				if err != nil {
					return err
				}
				fresh := *hc
				fresh.Jar = jar
				_, err = signIn(ctx, &fresh, e)
				return err
			}, nil
		},
	},
	"passkey": {
		help: "sign in with a passkey from a software authenticator, enrolled after one signin per worker", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			// A person of its own, past those -people names: a passkey is a second
			// factor, so a second worker's password sign-in would be asked for one.
			person := *e.cfg
			person.Username = personName(e.cfg, e.cfg.People+int(nextWorker.Add(1)))
			d, err := driverFor(e.cfg)
			if err != nil {
				return nil, err
			}
			enrol, use := enrolPasskey, (*softPasskey).signIn
			if d.enrol != nil {
				enrol, use = d.enrol, d.passkey
			}
			self := &env{cfg: &person, md: e.md}
			key, err := enrol(ctx, hc, self)
			if err != nil {
				return nil, fmt.Errorf("enrolling a passkey: %w", err)
			}
			return func(ctx context.Context) error {
				jar, err := cookiejar.New(nil)
				if err != nil {
					return err
				}
				fresh := *hc
				fresh.Jar = jar
				// Usernameless where the product allows it; where it asks for the name
				// first, the worker's own person's.
				return use(key, ctx, &fresh, self)
			}, nil
		},
	},
	"mfa": {
		help: "spend a TOTP code at sign-in, -people taking turns as a code is good once; the password is outside the latency", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if (e.cfg.TOTPSeed == "" && e.cfg.TOTPSeeds == "") || e.cfg.People < 1 {
				return nil, fmt.Errorf("give -totp-seed or -totp-seeds, and -people")
			}
			seeds, err := readSeeds(e.cfg.TOTPSeeds)
			if err != nil {
				return nil, err
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				jar, err := cookiejar.New(nil)
				if err != nil {
					return err
				}
				fresh := *hc
				fresh.Jar = jar
				person := *e.cfg
				person.Username = personName(e.cfg, int(nextPerson.Add(1))%e.cfg.People+1)
				if seeds != nil {
					if person.TOTPSeed = seeds[person.Username]; person.TOTPSeed == "" {
						return fmt.Errorf("-totp-seeds has no secret for %s", person.Username)
					}
				}
				tok, err := signIn(ctx, &fresh, &env{cfg: &person, md: e.md})
				if err != nil {
					return err
				}
				if !tok.spentCode {
					return fmt.Errorf("%s signed in and was never asked for a code", person.Username)
				}
				return nil
			}, nil
		},
	},
	"end-session": {
		help: "sign out (RP-Initiated Logout), each from a sign-in kept out of the latency", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.md.EndSessionEndpoint == "" {
				return nil, fmt.Errorf("the provider advertises no end session endpoint")
			}
			base := httpClient(e.cfg)
			return func(ctx context.Context) error {
				// A browser of its own for each person, signed in and then out: one browser
				// passed from person to person is offered an account picker by a provider
				// that remembers who used it, which is not what is measured.
				jar, err := cookiejar.New(nil)
				if err != nil {
					return err
				}
				fresh := *base
				fresh.Jar = jar
				hc := &fresh
				var tok tokenResponse
				if err := outside(ctx, func() (err error) {
					tok, err = signIn(ctx, hc, asNextPerson(e))
					return err
				}); err != nil {
					return err
				}
				if tok.IDToken == "" {
					return fmt.Errorf("the sign-in issued no ID token; ask for openid with -scope")
				}
				at, err := url.Parse(e.md.EndSessionEndpoint + "?" + url.Values{
					"id_token_hint": {tok.IDToken}, "client_id": {e.cfg.ClientID}}.Encode())
				if err != nil {
					return err
				}
				// A provider may end the session on a page it redirects to rather than at the
				// endpoint, so the browser follows it while it stays on the provider's host,
				// as a person's would; leaving that host is the sign-out done.
				for hop := 0; hop < 5; hop++ {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, at.String(), nil)
					if err != nil {
						return err
					}
					resp, err := hc.Do(req)
					if err != nil {
						return err
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
					_ = resp.Body.Close()
					traceHop(hop, req, resp, body)
					if resp.StatusCode >= 400 {
						return fmt.Errorf("the sign-out at %s answered %d: %s", at.Path, resp.StatusCode, trim(body))
					}
					if resp.StatusCode < 300 || resp.StatusCode >= 400 {
						return nil
					}
					next, err := at.Parse(resp.Header.Get("Location"))
					if err != nil {
						return err
					}
					if next.Host != at.Host {
						return nil
					}
					at = next
				}
				return fmt.Errorf("the sign-out was still redirecting after five hops")
			}, nil
		},
	},
	"token-exchange": {
		help: "exchange a person's access token for another (RFC 8693), after one signin per worker", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			tok, err := signIn(ctx, hc, asNextPerson(e))
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				body, err := postForm(ctx, hc, e.md.TokenEndpoint, e.cfg, url.Values{
					"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"subject_token":      {tok.AccessToken},
					"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
				})
				if err != nil {
					return err
				}
				var next tokenResponse
				if err := json.Unmarshal(body, &next); err != nil || next.AccessToken == "" {
					return fmt.Errorf("the exchange answered %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"admin-list": {
		help: "a page of the Admin API's people, as an operator's tool reads it",
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.AdminURL == "" {
				return nil, fmt.Errorf("give -admin")
			}
			hc := httpClient(e.cfg)
			list := e.cfg.AdminList
			if list == "" {
				list = signariAdminList
			}
			at := strings.TrimRight(e.cfg.AdminURL, "/") + list
			return func(ctx context.Context) error {
				if e.cfg.AdminListBody == "" {
					_, err := get(ctx, hc, at, e.cfg.AdminToken)
					return err
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, at, strings.NewReader(e.cfg.AdminListBody))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+e.cfg.AdminToken)
				_, err = do(hc, req)
				return err
			}, nil
		},
	},
	"signin": {
		help: "a person's password sign-in, Signari's login form through to a redeemed authorization code", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.SignInPeople < 1 {
				return func(ctx context.Context) error {
					_, err := signIn(ctx, httpClient(e.cfg), e)
					return err
				}, nil
			}
			// With -signin-people, each sign-in is a different seeded person in a
			// browser of their own. One person signed in by every worker at once is
			// throttled by design, as each attempt is charged to the account before the
			// password is checked, so it measures the throttle and not sign-in.
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				jar, err := cookiejar.New(nil)
				if err != nil {
					return err
				}
				fresh := *hc
				fresh.Jar = jar
				_, err = signIn(ctx, &fresh, asNextPerson(e))
				return err
			}, nil
		},
	},
	"refresh": {
		help: "a refresh token chain, each refresh spending the last (after one signin per worker)", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			tok, err := signIn(ctx, hc, asNextPerson(e))
			if err != nil {
				return nil, err
			}
			if tok.RefreshToken == "" {
				return nil, fmt.Errorf("the sign-in issued no refresh token; ask for offline_access with -scope")
			}
			rt := tok.RefreshToken
			return func(ctx context.Context) error {
				body, err := postForm(ctx, hc, e.md.TokenEndpoint, e.cfg, url.Values{
					"grant_type": {"refresh_token"}, "refresh_token": {rt},
				})
				if err != nil {
					return err
				}
				var next tokenResponse
				if err := json.Unmarshal(body, &next); err != nil || next.AccessToken == "" {
					return fmt.Errorf("refresh answered %s", trim(body))
				}
				if next.RefreshToken != "" {
					rt = next.RefreshToken
				}
				return nil
			}, nil
		},
	},
	"userinfo": {
		help: "GET userinfo with a person's access token (after one signin per worker)", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			tok, err := signIn(ctx, hc, asNextPerson(e))
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				_, err := get(ctx, hc, e.md.UserinfoEndpoint, tok.AccessToken)
				return err
			}, nil
		},
	},
	"saml-sso": {
		help: "a SAML response to a service provider's AuthnRequest (redirect binding) for a person already signed in, after one signin per worker in a browser of its own; -saml-sso, -saml-sp, -saml-acs", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.SAMLSSO == "" || e.cfg.SAMLSP == "" {
				return nil, fmt.Errorf("saml-sso needs -saml-sso, the provider's single sign-on URL, and -saml-sp, the service provider")
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				return nil, err
			}
			fresh := *httpClient(e.cfg)
			fresh.Jar = jar
			hc := &fresh
			if _, err := signIn(ctx, hc, asNextPerson(e)); err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				at, err := authnRequestURL(e.cfg.SAMLSSO, e.cfg.SAMLSP, e.cfg.SAMLACS, time.Now())
				if err != nil {
					return err
				}
				body, err := get(ctx, hc, at, "")
				if err != nil {
					return err
				}
				// The auto-posting form carrying the response, which only a person the
				// provider recognised is given.
				if !bytes.Contains(body, []byte(`name="SAMLResponse"`)) {
					return fmt.Errorf("no SAMLResponse in the answer: %s", trim(body))
				}
				return nil
			}, nil
		},
	},
	"ldap-bind": {
		help: "an LDAP simple bind on an open connection",
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			conn, err := dialLDAP(e.cfg)
			if err != nil {
				return nil, err
			}
			dn := fmt.Sprintf(e.cfg.LDAPDNTemplate, ldap.EscapeDN(e.cfg.Username))
			return func(context.Context) error { return conn.Bind(dn, e.cfg.Password) }, nil
		},
	},
	"ldap-search": {
		help: "an LDAP subtree search for one person, bound once outside the window",
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			conn, err := dialLDAP(e.cfg)
			if err != nil {
				return nil, err
			}
			if err := conn.Bind(fmt.Sprintf(e.cfg.LDAPDNTemplate, ldap.EscapeDN(e.cfg.Username)), e.cfg.Password); err != nil {
				return nil, fmt.Errorf("binding: %w", err)
			}
			filter := fmt.Sprintf(e.cfg.LDAPFilter, ldap.EscapeFilter(e.cfg.Username))
			return func(context.Context) error {
				res, err := conn.Search(ldap.NewSearchRequest(e.cfg.LDAPBase, ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases, 0, 0, false, filter, []string{"uid", "mail"}, nil))
				if err != nil {
					return err
				}
				if len(res.Entries) == 0 {
					return fmt.Errorf("the search found nobody")
				}
				return nil
			}, nil
		},
	},
	"radius-pap": {
		help: "a RADIUS Access-Request with PAP, answered Access-Accept (RFC 2865)",
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.RADIUSAddr == "" || e.cfg.RADIUSSecret == "" {
				return nil, fmt.Errorf("give -radius and -radius-secret")
			}
			return func(ctx context.Context) error {
				return radiusPAP(ctx, e.cfg.RADIUSAddr, e.cfg.RADIUSSecret, e.cfg.Username, e.cfg.Password)
			}, nil
		},
	},
	"scim-list": {
		help: "GET the first hundred SCIM users (RFC 7644 §3.4.2)",
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.SCIMURL == "" {
				return nil, fmt.Errorf("give -scim")
			}
			hc := httpClient(e.cfg)
			return func(ctx context.Context) error {
				_, err := get(ctx, hc, strings.TrimRight(e.cfg.SCIMURL, "/")+"/Users?count=100", e.cfg.SCIMToken)
				return err
			}, nil
		},
	},
	"authzen": {
		help: "an AuthZEN access evaluation (POST /access/v1/evaluation)",
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			if e.cfg.PDPURL == "" {
				return nil, fmt.Errorf("give -pdp or -issuer")
			}
			hc := httpClient(e.cfg)
			endpoint := strings.TrimRight(e.cfg.PDPURL, "/") + "/access/v1/evaluation"
			return func(ctx context.Context) error {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
					strings.NewReader(e.cfg.AuthZENBody))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/json")
				if e.cfg.PDPToken != "" {
					req.Header.Set("Authorization", "Bearer "+e.cfg.PDPToken)
				}
				body, err := do(hc, req)
				if err != nil {
					return err
				}
				var out struct {
					Decision *bool `json:"decision"`
				}
				if err := json.Unmarshal(body, &out); err != nil || out.Decision == nil {
					return fmt.Errorf("no decision in %s", trim(body))
				}
				return nil
			}, nil
		},
	},
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`

	// spentCode says a TOTP code was asked for on the way. Without it a sign-in that
	// was never asked for one reads as a result, timed as the whole sign-in.
	spentCode bool
}

// asNextPerson is e signing in as the next of -signin-people when that is given, and
// as -username otherwise. Sixteen workers each signing one account in at once, or
// one after another for minutes, are throttled by design.
// readSeeds reads -totp-seeds, a line per person of their sign-in name and their TOTP
// secret in base32, for a product that makes each person's secret itself when they enrol.
// Empty, it is nil and -totp-seed serves everybody.
func readSeeds(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a file the operator of the bench names
	if err != nil {
		return nil, fmt.Errorf("-totp-seeds: %w", err)
	}
	seeds := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if name, seed, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			seeds[name] = strings.TrimSpace(seed)
		}
	}
	if len(seeds) == 0 {
		return nil, fmt.Errorf("-totp-seeds: no line of a name and a secret in %s", path)
	}
	return seeds, nil
}

// personName is the n'th person's sign-in name, by -person: bench-n@bench.invalid, as
// `bench seed` makes them, unless a product's people for a scenario are named apart.
func personName(c *config, n int) string {
	n += c.PersonOffset
	if c.PersonFormat == "" {
		return fmt.Sprintf("bench-%d@%s", n, benchDomain)
	}
	return fmt.Sprintf(c.PersonFormat, n)
}

func asNextPerson(e *env) *env {
	if e.cfg.SignInPeople < 1 {
		return e
	}
	person := *e.cfg
	person.Username = personName(e.cfg, int(nextPerson.Add(1))%e.cfg.SignInPeople+1)
	next := *e
	next.cfg = &person
	return &next
}

func clientCredentials(ctx context.Context, hc *http.Client, e *env) (tokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if e.cfg.CCScope != "" {
		form.Set("scope", e.cfg.CCScope)
	}
	body, err := postForm(ctx, hc, e.md.TokenEndpoint, e.cfg, form)
	if err != nil {
		return tokenResponse{}, err
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("no access token in %s", trim(body))
	}
	return tok, nil
}

// nextPerson is shared by the workers, so that they do not take the same turns, and
// nextWorker numbers them where each needs a person of its own.
var nextPerson, nextWorker atomic.Int64

// startDevice starts a device authorization and answers its device code.
func startDevice(ctx context.Context, hc *http.Client, e *env) (string, error) {
	// client_id is sent even when the client authenticates, which RFC 8628 §3.1 allows and
	// most device clients do; one provider refuses a start without it (E.21).
	body, err := postForm(ctx, hc, e.md.DeviceEndpoint, e.cfg, url.Values{"scope": {"openid"},
		"client_id": {e.cfg.ClientID}})
	if err != nil {
		return "", err
	}
	var out struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.DeviceCode == "" {
		return "", fmt.Errorf("no device_code came back: %s", trim(body))
	}
	return out.DeviceCode, nil
}

// postForm posts to an OAuth endpoint with the client's credentials: HTTP
// Basic when it has a secret, client_id in the body when it is public.
func postForm(ctx context.Context, hc *http.Client, endpoint string, c *config, form url.Values) ([]byte, error) {
	req, err := formRequest(ctx, endpoint, c, form)
	if err != nil {
		return nil, err
	}
	return do(hc, req)
}

// postFormStatus is postForm for a scenario whose success is not a 200: waiting on a
// device is a 400, by RFC 8628.
func postFormStatus(ctx context.Context, hc *http.Client, endpoint string, c *config, form url.Values) (int, []byte, error) {
	req, err := formRequest(ctx, endpoint, c, form)
	if err != nil {
		return 0, nil, err
	}
	return doStatus(hc, req)
}

func formRequest(ctx context.Context, endpoint string, c *config, form url.Values) (*http.Request, error) {
	if c.ClientSecret == "" {
		form.Set("client_id", c.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.ClientSecret != "" {
		// Form-encoded before Basic, as the engine's decoder expects
		// (engine/internal/oauth/token.go, parseBasic): a secret with a '+'
		// sent raw would otherwise arrive as a different secret.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	return req, nil
}

func get(ctx context.Context, hc *http.Client, u, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(hc, req)
}

// do sends the request and returns the body of a 200, or an error naming the
// status and the start of the body.
// doStatus answers a response whatever its status, but for a 429, which is load shed
// in every scenario.
func doStatus(hc *http.Client, req *http.Request) (int, []byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return 0, nil, shedError{fmt.Sprintf("%s answered 429: %s", req.URL.Path, trim(body))}
	}
	return resp.StatusCode, body, nil
}

func do(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, shedError{fmt.Sprintf("%s answered 429: %s", req.URL.Path, trim(body))}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// A bearer refusal says why in its challenge and has no body at all.
		return nil, fmt.Errorf("%s answered %d: %s %s", req.URL.Path, resp.StatusCode,
			resp.Header.Get("WWW-Authenticate"), trim(body))
	}
	return body, nil
}

// shedError is a 429: the server refusing load it was configured to refuse,
// which is the server working. Counted apart from failures, because folding
// the two together hides whether anything is actually broken.
type shedError struct{ msg string }

func (e shedError) Error() string { return e.msg }

func trim(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 160 {
		b = append(b[:160:160], "…"...)
	}
	return string(b)
}

func dialLDAP(c *config) (*ldap.Conn, error) {
	if c.LDAPAddr == "" {
		return nil, fmt.Errorf("give -ldap")
	}
	opts := []ldap.DialOpt{}
	if c.Insecure {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) // #nosec G402 -- asked for by -insecure
	}
	return ldap.DialURL(c.LDAPAddr, opts...)
}
