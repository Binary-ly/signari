package provision

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provisioning into Microsoft Entra ID, through Microsoft Graph.
//
// Entra is a SCIM *client*, not a SCIM server: you cannot provision into it
// over SCIM, only out of it. So accounts are written through Graph with an
// application registration holding User.ReadWrite.All.
//
// # accountEnabled, not delete
//
// Deleting an Entra user moves it to a recycle bin for thirty days and then
// destroys it along with its mailbox. `accountEnabled = false` is instant,
// reversible, and what deprovisioning means in practice.

// Entra provisions into a tenant.
type Entra struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// Domain is the verified domain new userPrincipalNames are created under.
	Domain string

	HTTP    *http.Client
	BaseURL string // overridden in tests
	AuthURL string

	token   string
	expires time.Time
}

func (e *Entra) base() string {
	if e.BaseURL != "" {
		return strings.TrimRight(e.BaseURL, "/")
	}
	return "https://graph.microsoft.com/v1.0"
}

func (e *Entra) client() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (e *Entra) bearer(ctx context.Context) (string, error) {
	if e.token != "" && time.Now().Before(e.expires) {
		return e.token, nil
	}
	authURL := e.AuthURL
	if authURL == "" {
		authURL = "https://login.microsoftonline.com/" + url.PathEscape(e.TenantID) +
			"/oauth2/v2.0/token"
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", e.ClientID)
	form.Set("client_secret", e.ClientSecret)
	// Application permissions. .default asks for whatever was consented to in
	// the portal, which for provisioning must include User.ReadWrite.All.
	form.Set("scope", "https://graph.microsoft.com/.default")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.client().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("entra token endpoint %s: %s", resp.Status,
			strings.TrimSpace(string(msg)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	e.token = out.AccessToken
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	e.expires = time.Now().Add(ttl - 5*time.Minute)
	return e.token, nil
}

type entraUser struct {
	ID                string `json:"id,omitempty"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName,omitempty"`
	Surname           string `json:"surname,omitempty"`
	MailNickname      string `json:"mailNickname,omitempty"`
	AccountEnabled    bool   `json:"accountEnabled"`
	Mail              string `json:"mail,omitempty"`

	PasswordProfile *struct {
		Password                      string `json:"password"`
		ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
	} `json:"passwordProfile,omitempty"`
}

func toUserFromEntra(u entraUser) User {
	return User{
		RemoteID:    u.ID,
		UserName:    u.UserPrincipalName,
		Email:       firstNonEmpty(u.Mail, u.UserPrincipalName),
		DisplayName: u.DisplayName,
		GivenName:   u.GivenName,
		FamilyName:  u.Surname,
		Active:      u.AccountEnabled,
	}
}

// CreateUser adds an account.
func (e *Entra) CreateUser(ctx context.Context, u User) (string, error) {
	upn := u.UserName
	if !strings.Contains(upn, "@") {
		if e.Domain == "" {
			return "", fmt.Errorf("%q is not a userPrincipalName and no domain is "+
				"configured to complete it", upn)
		}
		upn = upn + "@" + e.Domain
	}
	nick := upn
	if i := strings.Index(nick, "@"); i > 0 {
		nick = nick[:i]
	}

	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	body := entraUser{
		UserPrincipalName: upn,
		DisplayName:       firstNonEmpty(u.DisplayName, u.UserName),
		GivenName:         u.GivenName,
		Surname:           u.FamilyName,
		MailNickname:      nick,
		AccountEnabled:    u.Active,
	}
	// Entra requires a password profile at creation. A long random one is set
	// and never recorded: sign-in happens through Signari, and a password nobody
	// knows is safer than a placeholder somebody might reuse.
	body.PasswordProfile = &struct {
		Password                      string `json:"password"`
		ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
	}{Password: pw, ForceChangePasswordNextSignIn: false}

	var created entraUser
	if err := e.call(ctx, http.MethodPost, "/users", body, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// SetActive enables or disables an account.
func (e *Entra) SetActive(ctx context.Context, remoteID string, active bool) error {
	return e.call(ctx, http.MethodPatch, "/users/"+url.PathEscape(remoteID),
		map[string]any{"accountEnabled": active}, nil)
}

// DeleteUser removes an account, recoverable for thirty days.
func (e *Entra) DeleteUser(ctx context.Context, remoteID string) error {
	return e.call(ctx, http.MethodDelete, "/users/"+url.PathEscape(remoteID), nil, nil)
}

// FindByUserName looks a person up by userPrincipalName.
func (e *Entra) FindByUserName(ctx context.Context, userName string) (*User, error) {
	var u entraUser
	if err := e.call(ctx, http.MethodGet, "/users/"+url.PathEscape(userName),
		nil, &u); err != nil {
		return nil, err
	}
	out := toUserFromEntra(u)
	return &out, nil
}

// ListUsers reads the tenant, following Graph's paging.
func (e *Entra) ListUsers(ctx context.Context, pageSize int) ([]User, error) {
	if pageSize <= 0 || pageSize > 999 {
		pageSize = 200
	}
	path := fmt.Sprintf("/users?$top=%d&$select=id,userPrincipalName,displayName,"+
		"givenName,surname,accountEnabled,mail", pageSize)

	var out []User
	for {
		var page struct {
			Value    []entraUser `json:"value"`
			NextLink string      `json:"@odata.nextLink"`
		}
		if err := e.call(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, u := range page.Value {
			out = append(out, toUserFromEntra(u))
		}
		if page.NextLink == "" {
			return out, nil
		}
		// Graph returns an absolute URL. Trimming the base back off keeps call()
		// working with one notion of a path.
		path = strings.TrimPrefix(page.NextLink, e.base())
		if strings.HasPrefix(path, "http") {
			// A different host entirely, which Graph does for some tenants.
			return out, nil
		}
	}
}

func (e *Entra) call(ctx context.Context, method, path string, body, out any) error {
	tok, err := e.bearer(ctx)
	if err != nil {
		return err
	}
	var rdr io.Reader
	if body != nil {
		raw, merr := json.Marshal(body)
		if merr != nil {
			return merr
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("microsoft graph %s %s: %s: %s", method, path, resp.Status,
			strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// randomPassword produces one nobody records.
//
// Both Google and Entra insist on a password at account creation, and neither
// account is meant to be signed into directly — authentication happens through
// Signari. So the password is long, random, and deliberately discarded: an
// account with a password nobody knows is safer than one with a placeholder
// somebody reuses across a tenant.
func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	// Both providers require mixed character classes; the suffix guarantees it
	// regardless of what the random bytes encoded to.
	return base64.RawURLEncoding.EncodeToString(raw) + "aA1!", nil
}
