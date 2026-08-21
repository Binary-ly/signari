package directory

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Google Workspace, through the Admin SDK Directory API.
//
// # Why a service account and an impersonated subject
//
// A Workspace service account reads nothing on its own. It needs domain-wide
// delegation, granted in the admin console, and every request must name a real
// administrator to act as. An operator who supplies a key without doing the
// delegation gets a 403 that says nothing useful, so the error here says it
// instead.
//
// # Why the JWT is signed here
//
// The service account flow is RFC 7523: sign an assertion with the account's
// private key, exchange it for an access token. That is fifty lines and no
// dependency, against a Google SDK that pulls in a large tree for the same
// thing. This engine already signs JWTs for a living.

// GoogleCredentials is the service account JSON Google issues.
type GoogleCredentials struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// ParseGoogleCredentials reads a service account key file.
func ParseGoogleCredentials(raw []byte) (*GoogleCredentials, error) {
	var c GoogleCredentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("this is not a Google service account key: %w", err)
	}
	if c.Type != "service_account" {
		return nil, fmt.Errorf("expected a service_account key, got type %q. An OAuth "+
			"client secret will not work: reading a directory needs a service account "+
			"with domain-wide delegation", c.Type)
	}
	if c.ClientEmail == "" || c.PrivateKey == "" {
		return nil, fmt.Errorf("the service account key is missing client_email or private_key")
	}
	if c.TokenURI == "" {
		c.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &c, nil
}

// GoogleSource reads users from a Workspace domain.
type GoogleSource struct {
	Creds *GoogleCredentials
	// Impersonate is the administrator the service account acts as. Required:
	// domain-wide delegation is meaningless without a subject.
	Impersonate string
	Domain      string
	// Query is Google's user search syntax, empty for everybody.
	Query string

	Client *http.Client
	// BaseURL is overridden in tests. Production leaves it empty.
	BaseURL string
}

func (g *GoogleSource) baseURL() string {
	if g.BaseURL != "" {
		return g.BaseURL
	}
	return "https://admin.googleapis.com"
}

func (g *GoogleSource) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Fetch returns every user the credential can see.
//
// Pagination is followed to the end, and a failure part-way through is an ERROR
// rather than a short list. That distinction is the whole safety story: a
// truncated page returned as success looks exactly like a company where
// everybody left, and the reconciler downstream would act on it.
func (g *GoogleSource) Fetch(ctx context.Context) ([]RemoteUser, error) {
	if g.Impersonate == "" {
		return nil, fmt.Errorf("no administrator to impersonate. A Google service " +
			"account reads nothing on its own: grant domain-wide delegation in the " +
			"admin console and set -impersonate to an administrator's address")
	}

	token, err := g.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	var out []RemoteUser
	pageToken := ""
	for page := 0; ; page++ {
		if page > 500 {
			// A pagination loop that never terminates would otherwise consume
			// memory until the process dies. 500 pages is 250,000 users at
			// Google's maximum page size.
			return nil, fmt.Errorf("the user list did not terminate after %d pages; "+
				"refusing to continue rather than growing without bound", page)
		}

		q := url.Values{}
		q.Set("maxResults", "500")
		if g.Domain != "" {
			q.Set("domain", g.Domain)
		} else {
			q.Set("customer", "my_customer")
		}
		if g.Query != "" {
			q.Set("query", g.Query)
		}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}

		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet,
			g.baseURL()+"/admin/directory/v1/users?"+q.Encode(), nil)
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, derr := g.client().Do(req)
		if derr != nil {
			return nil, fmt.Errorf("reading the Google directory: %w", derr)
		}

		var body struct {
			Users []struct {
				ID           string `json:"id"`
				PrimaryEmail string `json:"primaryEmail"`
				Name         struct {
					FullName string `json:"fullName"`
				} `json:"name"`
				Suspended bool `json:"suspended"`
				Archived  bool `json:"archived"`
			} `json:"users"`
			NextPageToken string `json:"nextPageToken"`
			Error         struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			msg := body.Error.Message
			if resp.StatusCode == http.StatusForbidden {
				msg += " -- this usually means domain-wide delegation is not granted " +
					"for this service account, or the impersonated administrator " +
					"lacks the directory scope"
			}
			return nil, fmt.Errorf("Google answered %d: %s", resp.StatusCode, msg)
		}
		if decErr != nil {
			return nil, fmt.Errorf("Google's answer did not parse: %w", decErr)
		}

		for _, u := range body.Users {
			out = append(out, RemoteUser{
				ID:    u.ID,
				Email: u.PrimaryEmail,
				Name:  u.Name.FullName,
				// Archived users are gone in every sense that matters here, and
				// Google reports them separately from suspended.
				Suspended: u.Suspended || u.Archived,
			})
		}

		pageToken = body.NextPageToken
		if pageToken == "" {
			return out, nil
		}
	}
}

// ScopeDirectoryRead is what a sync needs: the ability to read the directory.
//
// A sync that can WRITE to somebody's Workspace directory is a far larger blast
// radius than reading it, and the scope is where that is decided. Provisioning
// asks for ScopeDirectoryWrite explicitly, so the two capabilities are separate
// tokens and a compromised sync cannot create accounts.
const (
	ScopeDirectoryRead  = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	ScopeDirectoryWrite = "https://www.googleapis.com/auth/admin.directory.user"
)

// GoogleToken exchanges a service account assertion for a bearer token.
//
// Exported so provisioning can ask for the write scope without a second copy of
// the JWT-bearer dance.
func GoogleToken(ctx context.Context, creds *GoogleCredentials, impersonate, scope string,
	hc *http.Client) (string, error) {

	g := &GoogleSource{Creds: creds, Impersonate: impersonate, Client: hc}
	return g.tokenForScope(ctx, scope)
}

// accessToken exchanges a signed assertion for a bearer token, RFC 7523.
func (g *GoogleSource) accessToken(ctx context.Context) (string, error) {
	return g.tokenForScope(ctx, ScopeDirectoryRead)
}

func (g *GoogleSource) tokenForScope(ctx context.Context, scope string) (string, error) {
	key, err := parsePrivateKey(g.Creds.PrivateKey)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   g.Creds.ClientEmail,
		"sub":   g.Impersonate,
		"aud":   g.Creds.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": scope,
	}

	assertion, err := signRS256(key, claims)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.Creds.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("exchanging the service account assertion: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("the token response did not parse: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("Google refused the service account assertion: %s %s",
			body.Error, body.ErrorDescription)
	}
	return body.AccessToken, nil
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("the service account private_key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("the service account key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// signRS256 builds a compact JWS. Small enough to keep here rather than reach
// for the engine's token package, which is shaped around this issuer's own keys.
func signRS256(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)

	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
