package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/directory"
)

// Provisioning into Google Workspace, through the Admin SDK Directory API.
//
// Google is not a SCIM server. Accounts are created and suspended through
// admin.googleapis.com, with a service account holding domain-wide delegation
// and impersonating an administrator — the same credential the inbound sync
// uses, with a wider scope asked for explicitly.
//
// # Suspend, never delete
//
// Deleting a Workspace account destroys the mailbox, the Drive files owned by
// it, and the calendar. Suspension is reversible and is what "deprovision"
// means for almost every organisation. DeleteUser exists because the interface
// has it and because some deployments genuinely want it, but the deactivation
// policy defaults elsewhere and this comment is why.

// Google provisions into a Workspace domain.
type Google struct {
	Creds       *directory.GoogleCredentials
	Impersonate string
	// Domain is the primary domain accounts are created in.
	Domain string

	HTTP    *http.Client
	BaseURL string // overridden in tests

	token   string
	expires time.Time
}

func (g *Google) base() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://admin.googleapis.com"
}

func (g *Google) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// bearer fetches a write-scoped token, cached until shortly before it expires.
func (g *Google) bearer(ctx context.Context) (string, error) {
	if g.token != "" && time.Now().Before(g.expires) {
		return g.token, nil
	}
	tok, err := directory.GoogleToken(ctx, g.Creds, g.Impersonate,
		directory.ScopeDirectoryWrite, g.client())
	if err != nil {
		return "", err
	}
	g.token = tok
	// Google's tokens last an hour. Fifty minutes leaves room for a long run
	// without re-authenticating on every request.
	g.expires = time.Now().Add(50 * time.Minute)
	return tok, nil
}

type googleUser struct {
	ID           string `json:"id,omitempty"`
	PrimaryEmail string `json:"primaryEmail"`
	Name         struct {
		GivenName  string `json:"givenName,omitempty"`
		FamilyName string `json:"familyName,omitempty"`
		FullName   string `json:"fullName,omitempty"`
	} `json:"name"`
	Suspended    bool   `json:"suspended"`
	Password     string `json:"password,omitempty"`
	ChangeAtNext bool   `json:"changePasswordAtNextLogin,omitempty"`
	ExternalIDs  []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"externalIds,omitempty"`
}

func (g *Google) toUser(u googleUser) User {
	out := User{
		ExternalID:  "",
		UserName:    u.PrimaryEmail,
		Email:       u.PrimaryEmail,
		DisplayName: u.Name.FullName,
		GivenName:   u.Name.GivenName,
		FamilyName:  u.Name.FamilyName,
		Active:      !u.Suspended,
	}
	for _, e := range u.ExternalIDs {
		if e.Type == "organization" {
			out.ExternalID = e.Value
		}
	}
	return out
}

// CreateUser adds an account.
func (g *Google) CreateUser(ctx context.Context, u User) (string, error) {
	if u.Email == "" {
		return "", fmt.Errorf("Google Workspace needs an email address; %q has none",
			u.UserName)
	}
	body := googleUser{PrimaryEmail: u.Email, Suspended: !u.Active}
	body.Name.GivenName = firstNonEmpty(u.GivenName, u.DisplayName, u.UserName)
	body.Name.FamilyName = firstNonEmpty(u.FamilyName, ".")
	body.Name.FullName = u.DisplayName
	// Google requires a password at creation. A long random one is set and never
	// recorded: the account signs in through Signari, and a password nobody
	// knows is better than a placeholder somebody might reuse.
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	body.Password = pw
	body.ChangeAtNext = false
	body.ExternalIDs = []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	}{{Value: u.ExternalID, Type: "organization"}}

	var created googleUser
	if err := g.call(ctx, http.MethodPost, "/admin/directory/v1/users", body, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// SetActive suspends or restores.
func (g *Google) SetActive(ctx context.Context, remoteID string, active bool) error {
	return g.call(ctx, http.MethodPut,
		"/admin/directory/v1/users/"+url.PathEscape(remoteID),
		map[string]any{"suspended": !active}, nil)
}

// DeleteUser removes an account permanently.
//
// Destroys the mailbox and everything owned by it. Suspension is what most
// deployments mean by deprovisioning, and this is here for the ones that do not.
func (g *Google) DeleteUser(ctx context.Context, remoteID string) error {
	return g.call(ctx, http.MethodDelete,
		"/admin/directory/v1/users/"+url.PathEscape(remoteID), nil, nil)
}

// FindByUserName looks a person up by primary email.
func (g *Google) FindByUserName(ctx context.Context, userName string) (*User, error) {
	var u googleUser
	err := g.call(ctx, http.MethodGet,
		"/admin/directory/v1/users/"+url.PathEscape(userName), nil, &u)
	if err != nil {
		return nil, err
	}
	out := g.toUser(u)
	out.RemoteID = u.ID
	return &out, nil
}

// ListUsers reads the domain.
func (g *Google) ListUsers(ctx context.Context, pageSize int) ([]User, error) {
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 200
	}
	var out []User
	pageToken := ""
	for {
		q := url.Values{}
		q.Set("domain", g.Domain)
		q.Set("maxResults", fmt.Sprint(pageSize))
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var page struct {
			Users         []googleUser `json:"users"`
			NextPageToken string       `json:"nextPageToken"`
		}
		if err := g.call(ctx, http.MethodGet,
			"/admin/directory/v1/users?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			user := g.toUser(u)
			// The remote id, which is what the link table stores and what every
			// later update addresses.
			user.RemoteID = u.ID
			out = append(out, user)
		}
		// Paged to the end rather than stopping at the first page. A sync that
		// reads only the first page decides every user beyond it is missing.
		if page.NextPageToken == "" {
			return out, nil
		}
		pageToken = page.NextPageToken
	}
}

func (g *Google) call(ctx context.Context, method, path string, body, out any) error {
	tok, err := g.bearer(ctx)
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
	req, err := http.NewRequestWithContext(ctx, method, g.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("google admin API %s %s: %s: %s",
			method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
