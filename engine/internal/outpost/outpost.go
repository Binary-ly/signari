// Package outpost runs Signari's protocol servers away from the database.
//
// An outpost is the same binary, started differently: it serves LDAP, RADIUS or
// forward auth in a DMZ, a branch office or an airgapped segment, and holds no
// database credentials at all. Every credential question goes to the core over
// HTTPS.
//
// # Why this is small
//
// internal/ldapd and internal/radius were written against a narrow
// Authenticator interface and have no database references. An outpost is
// therefore a second implementation of that interface -- this file -- rather
// than a second architecture. The comparable feature elsewhere in this field
// needed its own component because the core and the protocol servers were
// written in different languages.
//
// # What an outpost token is worth
//
// It is a password-verification oracle. Anyone holding one can ask "is this
// password correct for this user" as fast as the core will answer. So:
//
//   - the token is bound to ONE protocol, and the core refuses it for another
//   - the core rate limits per outpost, not just per user
//   - the core records every use, so a token being exercised from a new address
//     is visible
//
// It is deliberately NOT enough to read the directory in bulk, change anything,
// or mint a session.
package outpost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"signari.dev/engine/internal/ldapd"
)

// Client asks a core to verify credentials.
type Client struct {
	core   string
	token  string
	http   *http.Client
	origin string
}

// New returns a client for a core.
func New(core, token string, timeout time.Duration) (*Client, error) {
	core = strings.TrimRight(core, "/")
	if core == "" {
		return nil, fmt.Errorf("give -core, the URL of the Signari engine this " +
			"outpost asks")
	}
	if !strings.HasPrefix(core, "https://") &&
		!strings.HasPrefix(core, "http://localhost") &&
		!strings.HasPrefix(core, "http://127.0.0.1") {
		return nil, fmt.Errorf("-core must be https: %q would carry every password "+
			"this outpost verifies across the network in the clear, which is the "+
			"one thing an outpost must never do", core)
	}
	if token == "" {
		return nil, fmt.Errorf("give -outpost-token, issued by `signari outpost create`")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{core: core, token: token, http: &http.Client{Timeout: timeout}}, nil
}

// Check verifies the outpost can reach the core and that its token works.
//
// Called before any listener is opened. An outpost that starts anyway and
// discovers its token is wrong on the first user's login has turned a
// configuration error into an outage, and the person who finds out is somebody
// trying to log in.
func (c *Client) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.core+"/outpost/hello", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the core at %s: %w", c.core, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		c.origin = out.Name
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("the core refused this outpost token. It may have been "+
			"revoked, or issued for a different protocol -- a token created for "+
			"one protocol is not accepted for another (core said %s)", resp.Status)
	default:
		return fmt.Errorf("the core answered %s", resp.Status)
	}
}

// Name is what the core calls this outpost, once Check has run.
func (c *Client) Name() string { return c.origin }

type identityJSON struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Active      bool     `json:"active"`
	Groups      []string `json:"groups"`
	// Absent from an engine that predates them, which is why the directory has a
	// fallback for `sn` rather than requiring one here.
	Surname   string `json:"sn"`
	GivenName string `json:"given_name"`
}

func (i identityJSON) toLDAP() *ldapd.Identity {
	return &ldapd.Identity{
		Username: i.Username, Email: i.Email, DisplayName: i.DisplayName,
		Active: i.Active, Groups: i.Groups,
		Surname: i.Surname, GivenName: i.GivenName,
	}
}

// ErrRefused is returned for any credential the core did not accept.
//
// One error for every reason, matching what the interface requires: "no such
// user" and "wrong password" must be indistinguishable, and an outpost that
// leaked the difference would be a user-enumeration endpoint reachable from
// wherever it is deployed -- which is, by design, somewhere less trusted.
var ErrRefused = fmt.Errorf("authentication refused")

// Authenticate verifies a password through the core.
func (c *Client) Authenticate(ctx context.Context, username, password string) (
	*ldapd.Identity, error) {

	var out identityJSON
	if err := c.post(ctx, "/outpost/authenticate", map[string]string{
		"username": username, "password": password,
	}, &out); err != nil {
		return nil, err
	}
	return out.toLDAP(), nil
}

// AuthenticatePassword is the RADIUS interface: correct or not, nothing more.
func (c *Client) AuthenticatePassword(ctx context.Context, username, password string) error {
	_, err := c.Authenticate(ctx, username, password)
	return err
}

// Lookup finds a user without a credential, for LDAP search.
func (c *Client) Lookup(ctx context.Context, username string) (*ldapd.Identity, error) {
	var out identityJSON
	if err := c.post(ctx, "/outpost/lookup", map[string]string{
		"username": username,
	}, &out); err != nil {
		return nil, err
	}
	return out.toLDAP(), nil
}

// List returns users for a subtree search.
func (c *Client) List(ctx context.Context, limit int) ([]*ldapd.Identity, error) {
	var out struct {
		Users []identityJSON `json:"users"`
	}
	if err := c.post(ctx, "/outpost/list", map[string]any{"limit": limit}, &out); err != nil {
		return nil, err
	}
	ids := make([]*ldapd.Identity, 0, len(out.Users))
	for _, u := range out.Users {
		ids = append(ids, u.toLDAP())
	}
	return ids, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.core+path,
		bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// A core that cannot be reached is NOT an authentication failure. Saying
		// "wrong password" when the network is down sends everybody to reset
		// their password during an outage, which makes the outage worse.
		return fmt.Errorf("the core could not be reached: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	case http.StatusUnauthorized, http.StatusNotFound:
		return ErrRefused
	default:
		return fmt.Errorf("the core answered %s", resp.Status)
	}
}
