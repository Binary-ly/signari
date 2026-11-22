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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/radius"
	"signari.dev/engine/internal/safedial"
)

// VersionHeader is how a call says which release made it (8.31).
const VersionHeader = "Signari-Outpost-Version"

// Client asks a core to verify credentials.
type Client struct {
	core        string
	token       string
	http        *http.Client
	version     string
	origin      string
	kind        string
	searchGroup string
	coreVersion string
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
	// The default transport with the system's roots and SIGNARI_CA_BUNDLE's, as every
	// other call out of this binary trusts. It had the system's alone, so a core whose
	// certificate an internal authority issued could not be reached at all; running
	// the compose template in docs/outposts.md found it (November 2026).
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: safedial.Roots(), MinVersion: tls.VersionTLS12}
	return &Client{core: core, token: token, http: &http.Client{Timeout: timeout, Transport: transport}}, nil
}

// Check verifies the outpost can reach the core and that its token works.
//
// Called before any listener is opened. An outpost that starts anyway and
// discovers its token is wrong on the first user's login has turned a
// configuration error into an outage, and the person who finds out is somebody
// trying to log in.
func (c *Client) Check(ctx context.Context) error {
	out, err := c.hello(ctx)
	if err != nil {
		return err
	}
	c.origin, c.kind, c.searchGroup, c.coreVersion = out.Name, out.Kind, out.SearchGroup, out.CoreVersion
	return nil
}

type helloAnswer struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SearchGroup string `json:"search_group"`
	CoreVersion string `json:"core_version"`
}

func (c *Client) hello(ctx context.Context) (helloAnswer, error) {
	var out helloAnswer
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.core+"/outpost/hello", nil)
	if err != nil {
		return out, err
	}
	c.identify(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("cannot reach the core at %s: %w", c.core, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out, nil
	case http.StatusForbidden:
		return out, fmt.Errorf("the core has this outpost out of service: `signari outpost enable` puts "+
			"it back (core said %s)", resp.Status)
	case http.StatusUnauthorized:
		return out, fmt.Errorf("the core refused this outpost token. It may have been "+
			"rotated or removed, or never issued by this core (core said %s)", resp.Status)
	default:
		return out, fmt.Errorf("the core answered %s", resp.Status)
	}
}

// Heartbeat says hello to the core until ctx ends. Without it an outpost nobody
// happens to be using looks the same as one that has gone, and one that has lost
// its core says nothing until somebody tries to sign in.
func (c *Client) Heartbeat(ctx context.Context, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	lost := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, err := c.hello(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return
		case err != nil && !lost:
			log.Error("the outpost has lost its core", "err", err)
		case err == nil && lost:
			log.Info("the outpost has its core back")
		}
		lost = err != nil
	}
}

// Identify names the release this outpost is, which every call then tells the core.
func (c *Client) Identify(version string) { c.version = version }

// identify puts on a request what says who is asking.
func (c *Client) identify(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.version != "" {
		req.Header.Set(VersionHeader, c.version)
	}
}

// Name is what the core calls this outpost, once Check has run.
func (c *Client) Name() string { return c.origin }

// Kind is the protocol the token was issued for, once Check has run.
func (c *Client) Kind() string { return c.kind }

// CoreVersion is the release of the core, once Check has run. Empty from a core
// that predates saying.
func (c *Client) CoreVersion() string { return c.coreVersion }

// SearchGroup is the group the core records for this outpost, once Check has
// run: whose members may search the whole directory. The core enforces it
// whatever the outpost believes, so the outpost takes it from there rather
// than from its own environment, and the two cannot disagree.
func (c *Client) SearchGroup() string { return c.searchGroup }

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
	// Absent from a core that predates them, and the directory then claims no
	// POSIX class for this person.
	UIDNumber int `json:"uid_number"`
	// Only on an authenticate answer: what this connection presents with every
	// later lookup and list, so the core answers for the person who bound.
	BindProof string `json:"bind_proof,omitempty"`
	// Only on a list answer: where the next page carries on from. Absent from a
	// core that predates paging, and the directory then stops at that page.
	Position string `json:"position,omitempty"`
}

func (i identityJSON) toLDAP() *ldapd.Identity {
	return &ldapd.Identity{
		Username: i.Username, Email: i.Email, DisplayName: i.DisplayName,
		Active: i.Active, Groups: i.Groups,
		Surname: i.Surname, GivenName: i.GivenName, UIDNumber: i.UIDNumber,
		BindProof: i.BindProof, Position: i.Position,
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
		"username": username, "password": password, "client_ip": ldapd.PeerAddr(ctx),
	}, &out); err != nil {
		return nil, err
	}
	return out.toLDAP(), nil
}

// RADIUS is this client as a RADIUS server's Authenticator: correct or not,
// nothing more.
type RADIUS struct{ *Client }

// Authenticate verifies a password through the core.
func (r RADIUS) Authenticate(ctx context.Context, username, password string) error {
	_, err := r.Client.Authenticate(ctx, username, password)
	if errors.Is(err, ldapd.ErrUnavailable) {
		return fmt.Errorf("%w: %w", radius.ErrUnavailable, err)
	}
	return err
}

// ReadRADIUSClients reads the devices a RADIUS outpost answers, a file of
// `name network secret` lines, blank lines and #-comments aside.
//
// A local file and not the core's own list, because each device's secret is a
// credential for that device, and an outpost is by design somewhere less trusted
// than the core: it holds the secrets of the devices it serves and no others. So
// the file has to be as private as a key, and a loose one is refused.
func ReadRADIUSClients(path string) ([]radius.Client, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s holds shared secrets and is readable beyond its owner (%v): chmod 600 it",
			path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own -radius-clients.
	if err != nil {
		return nil, err
	}
	var out []radius.Client
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			// The line number and not the line: it holds a secret.
			return nil, fmt.Errorf("%s line %d: want `name network secret`", path, i+1)
		}
		network, err := radius.ClientNetwork(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		if err := radius.ValidSecret(fields[2]); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		out = append(out, radius.Client{Name: fields[0], Net: network, Secret: fields[2]})
	}
	return out, nil
}

// Lookup finds a user without a credential, for LDAP search. The core answers
// only for the person whose bind proof the connection carries: their own entry,
// or anyone's when they are in this outpost's search group.
func (c *Client) Lookup(ctx context.Context, username string) (*ldapd.Identity, error) {
	var out identityJSON
	if err := c.post(ctx, "/outpost/lookup", map[string]string{
		"username": username, "bind_proof": ldapd.BindProof(ctx),
	}, &out); err != nil {
		return nil, err
	}
	return out.toLDAP(), nil
}

// List returns a page of users for a subtree search: the directory for a member
// of this outpost's search group, the asker's own entry for anyone else.
func (c *Client) List(ctx context.Context, q ldapd.Query) ([]*ldapd.Identity, error) {
	var out struct {
		Users []identityJSON `json:"users"`
	}
	err := c.post(ctx, "/outpost/list", map[string]any{
		"limit": q.Limit, "after": q.After, "narrow": q.Narrow, "bind_proof": ldapd.BindProof(ctx),
	}, &out)
	if errors.Is(err, errBadRequest) && q.After != "" {
		return nil, ldapd.ErrBadPosition
	}
	if err != nil {
		return nil, err
	}
	ids := make([]*ldapd.Identity, 0, len(out.Users))
	for _, u := range out.Users {
		ids = append(ids, u.toLDAP())
	}
	return ids, nil
}

// Groups returns a page of the group entries, for a member of this outpost's
// search group. A core that predates them answers 404, and that is a directory
// with no groups rather than a failed search, so a subtree search, which asks
// for both, keeps working through a rolling upgrade.
func (c *Client) Groups(ctx context.Context, q ldapd.Query) ([]*ldapd.Group, error) {
	var out struct {
		Groups []*ldapd.Group `json:"groups"`
	}
	err := c.post(ctx, "/outpost/groups", map[string]any{
		"limit": q.Limit, "after": q.After, "narrow": q.Narrow, "bind_proof": ldapd.BindProof(ctx),
	}, &out)
	switch {
	case errors.Is(err, ErrRefused):
		return nil, nil
	case errors.Is(err, errBadRequest) && q.After != "":
		return nil, ldapd.ErrBadPosition
	case err != nil:
		return nil, err
	}
	return out.Groups, nil
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
	c.identify(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// A core that cannot be reached is NOT an authentication failure. Saying
		// "wrong password" when the network is down sends everybody to reset
		// their password during an outage, which makes the outage worse.
		return fmt.Errorf("%w: %w", ldapd.ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
			return fmt.Errorf("%w: reading the core's answer: %w", ldapd.ErrUnavailable, err)
		}
		return nil
	case http.StatusUnauthorized:
		// Refused or rotated, the one word that tells them apart. A token the core
		// has stopped taking is an outage to whoever is behind this outpost.
		if strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
			return fmt.Errorf("%w: the core no longer takes this outpost's token", ldapd.ErrUnavailable)
		}
		return ErrRefused
	case http.StatusNotFound:
		return ErrRefused
	case http.StatusBadRequest:
		return errBadRequest
	case http.StatusTooManyRequests:
		return ldapd.ErrBusy
	default:
		return fmt.Errorf("%w: the core answered %s", ldapd.ErrUnavailable, resp.Status)
	}
}

// errBadRequest is the core refusing what it was asked.
var errBadRequest = errors.New("the core refused the request as malformed")
