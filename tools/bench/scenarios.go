package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
}

type env struct {
	cfg *config
	md  discovery
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
			tok, err := clientCredentials(ctx, hc, e)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				body, err := postForm(ctx, hc, e.md.IntrospectionEndpoint, e.cfg, url.Values{"token": {tok.AccessToken}})
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
	"signin": {
		help: "a person's password sign-in, Signari's login form through to a redeemed authorization code", needsDiscovery: true,
		worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
			return func(ctx context.Context) error {
				_, err := signIn(ctx, httpClient(e.cfg), e)
				return err
			}, nil
		},
	},
	"refresh": {
		help: "a refresh token chain, each refresh spending the last (after one signin per worker)", needsDiscovery: true,
		worker: func(ctx context.Context, e *env) (func(context.Context) error, error) {
			hc := httpClient(e.cfg)
			tok, err := signIn(ctx, hc, e)
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
			tok, err := signIn(ctx, hc, e)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) error {
				_, err := get(ctx, hc, e.md.UserinfoEndpoint, tok.AccessToken)
				return err
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
			filter := "(uid=" + ldap.EscapeFilter(e.cfg.Username) + ")"
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

// postForm posts to an OAuth endpoint with the client's credentials: HTTP
// Basic when it has a secret, client_id in the body when it is public.
func postForm(ctx context.Context, hc *http.Client, endpoint string, c *config, form url.Values) ([]byte, error) {
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
	return do(hc, req)
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d: %s", req.URL.Path, resp.StatusCode, trim(body))
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
