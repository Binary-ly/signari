package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Microsoft Entra ID, through Microsoft Graph.
//
// Simpler than Google: a confidential client with application permissions, the
// ordinary client_credentials grant, no impersonation. The complexity is on the
// other side -- Graph paginates with an absolute @odata.nextLink rather than a
// token, and that link must be followed as given.

// EntraCredentials is an app registration.
type EntraCredentials struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ParseEntraCredentials reads them from JSON.
func ParseEntraCredentials(raw []byte) (*EntraCredentials, error) {
	var c EntraCredentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("this is not an Entra credential file: %w", err)
	}
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("an Entra credential needs tenant_id, client_id and " +
			"client_secret")
	}
	return &c, nil
}

// EntraSource reads users from a tenant.
type EntraSource struct {
	Creds *EntraCredentials
	// Filter is OData, empty for everybody.
	Filter string

	Client   *http.Client
	BaseURL  string // overridden in tests
	TokenURL string // overridden in tests
}

func (e *EntraSource) baseURL() string {
	if e.BaseURL != "" {
		return e.BaseURL
	}
	return "https://graph.microsoft.com"
}

func (e *EntraSource) tokenURL() string {
	if e.TokenURL != "" {
		return e.TokenURL
	}
	return "https://login.microsoftonline.com/" + e.Creds.TenantID + "/oauth2/v2.0/token"
}

func (e *EntraSource) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Fetch returns every user in the tenant.
//
// Like the Google adapter, a failure part-way through pagination is an error and
// never a short list: the reconciler downstream cannot tell the difference
// between "these are all the users" and "these are the users we managed to read
// before something broke", so this layer must not blur it.
func (e *EntraSource) Fetch(ctx context.Context) ([]RemoteUser, error) {
	token, err := e.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("$select", "id,userPrincipalName,displayName,accountEnabled,mail")
	q.Set("$top", "999")
	if e.Filter != "" {
		q.Set("$filter", e.Filter)
	}
	next := e.baseURL() + "/v1.0/users?" + q.Encode()

	var out []RemoteUser
	for page := 0; next != ""; page++ {
		if page > 500 {
			return nil, fmt.Errorf("the user list did not terminate after %d pages; "+
				"refusing to continue rather than growing without bound", page)
		}

		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, derr := e.client().Do(req)
		if derr != nil {
			return nil, fmt.Errorf("reading the Entra directory: %w", derr)
		}

		var body struct {
			Value []struct {
				ID                string `json:"id"`
				UserPrincipalName string `json:"userPrincipalName"`
				Mail              string `json:"mail"`
				DisplayName       string `json:"displayName"`
				AccountEnabled    bool   `json:"accountEnabled"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
			Error    struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&body)
		status := resp.StatusCode
		_ = resp.Body.Close()

		if status != http.StatusOK {
			msg := body.Error.Message
			if status == http.StatusForbidden {
				msg += " -- this usually means the app registration lacks the " +
					"User.Read.All application permission, or admin consent was " +
					"never granted for it"
			}
			return nil, fmt.Errorf("Microsoft Graph answered %d: %s", status, msg)
		}
		if decErr != nil {
			return nil, fmt.Errorf("Graph's answer did not parse: %w", decErr)
		}

		for _, u := range body.Value {
			// mail is the routable address and is often empty; the principal name
			// always exists. Preferring mail and falling back is what matches how
			// people actually sign in.
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			out = append(out, RemoteUser{
				ID:        u.ID,
				Email:     email,
				Name:      u.DisplayName,
				Suspended: !u.AccountEnabled,
			})
		}

		// Followed as given. Graph's nextLink is absolute and carries opaque
		// skip tokens; rebuilding the query from parts silently loses them and
		// re-reads page one forever.
		next = body.NextLink
	}
	return out, nil
}

func (e *EntraSource) accessToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", e.Creds.ClientID)
	form.Set("client_secret", e.Creds.ClientSecret)
	// Application permissions, not delegated. The .default scope asks for
	// whatever was consented to in the portal.
	form.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("getting an Entra access token: %w", err)
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
		return "", fmt.Errorf("Entra refused the credential: %s %s",
			body.Error, body.ErrorDescription)
	}
	return body.AccessToken, nil
}
