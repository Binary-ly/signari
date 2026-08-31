// Package scim implements outbound SCIM 2.0 provisioning (RFC 7643, RFC 7644).
//
// # Which half of this matters
//
// Provisioning failing is a support ticket. Somebody cannot get into Slack and
// says so within the hour.
//
// DEPROVISIONING failing is a security incident nobody reports, because the
// person it affects has left and the administrator who deactivated them saw a
// success message. Months later an audit finds an active account for somebody
// who resigned last spring.
//
// So this package is built around being able to PROVE the second one worked.
// Every remote account is recorded with the id the target assigned it, and
// `signari scim verify` goes and reads the target's actual state back rather
// than trusting what we recorded when we sent it.
package scim

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
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

	// contentType is what RFC 7644 specifies. Several targets accept
	// application/json as well, and at least as many reject it.
	contentType = "application/scim+json"

	defaultTimeout = 20 * time.Second
)

// Target is a configured downstream application.
type Target struct {
	ID           string
	OrgID        string
	Slug         string
	DisplayName  string
	BaseURL      string
	Token        string
	DryRun       bool
	OnDeactivate string

	// Kind is scim, google or entra. Empty means scim, for targets registered
	// before native provisioning existed.
	Kind string
	// Credentials is the unsealed service account or client secret for a native
	// target. Empty for SCIM.
	Credentials []byte
	// Impersonate is the administrator a Google service account acts as.
	Impersonate string
	// TargetDomain is the domain new accounts are created under.
	TargetDomain string

	// ScopeGroupID restricts provisioning to one group's members.
	//
	// Empty provisions every active user in the organisation, which is what
	// every target did before this existed. Narrowing an existing target is a
	// mass DEPROVISION at the remote system -- the next reconciliation sees
	// accounts that should no longer exist and deactivates them -- which is
	// exactly the shape provision.CheckSafety refuses above 25%.
	ScopeGroupID string
}

// User is the subset of the SCIM user schema we send.
//
// Deliberately small. SCIM's user schema is large and mostly optional, and
// every attribute sent is an attribute that can be rejected by a target with a
// stricter idea of what it accepts -- so this carries what is needed to create
// a working account and nothing else.
type User struct {
	Schemas     []string `json:"schemas"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Active      bool     `json:"active"`
	Name        *Name    `json:"name,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`

	// ID is assigned BY THE TARGET and only ever read, never sent.
	ID string `json:"id,omitempty"`
}

// InboundUser is a User as an UPSTREAM sends it.
//
// The one difference is Active, and it matters: as a plain bool, a create that
// omits `active` decodes as false and silently provisions a disabled account.
// The person is then told their brand new account does not work, and the
// upstream reports a successful sync. SCIM leaves the attribute optional, so
// absence has to mean "not stated" rather than "no".
type InboundUser struct {
	User
	Active *bool `json:"active"`
}

// ActiveOrDefault reads the flag, defaulting to active when it was not sent.
func (u InboundUser) ActiveOrDefault() bool {
	if u.Active == nil {
		return true
	}
	return *u.Active
}

// Resolved returns the user with Active filled in from the pointer.
func (u InboundUser) Resolved() User {
	out := u.User
	out.Active = u.ActiveOrDefault()
	return out
}

type Name struct {
	Formatted string `json:"formatted,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// NewUser builds a SCIM user from our own record.
//
// externalID is OUR user id, sent so the target can correlate back to us. It is
// the value that makes a re-provision idempotent at targets that honour it.
func NewUser(externalID, userName, displayName, email string, active bool) User {
	u := User{
		Schemas:    []string{schemaUser},
		ExternalID: externalID,
		UserName:   userName,
		Active:     active,
	}
	if displayName != "" {
		u.Name = &Name{Formatted: displayName}
	}
	if email != "" {
		u.Emails = []Email{{Value: email, Primary: true, Type: "work"}}
	}
	return u
}

// Client talks to one target.
type Client struct {
	target Target
	http   *http.Client
}

func NewClient(t Target, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{target: t, http: hc}
}

// Error is a SCIM error response, kept structured so the caller can decide
// whether a failure is worth retrying.
type Error struct {
	Status int
	Detail string
	// Conflict marks 409, which for a create means the account already exists --
	// not a failure to retry forever, but a signal to go and find its id.
	Conflict bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("the target answered %d: %s", e.Status, e.Detail)
}

// Retryable reports whether trying again could plausibly succeed.
//
// The distinction is what stops a queue burning attempts on a request that will
// never work -- a 400 from a target that rejects an attribute is not going to
// start working on the fifth try, and retrying it hides the real problem behind
// a growing backlog.
func (e *Error) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// CreateUser provisions a user and returns the id the target assigned.
func (c *Client) CreateUser(ctx context.Context, u User) (string, error) {
	if c.target.DryRun {
		return "", nil
	}
	var created User
	if err := c.do(ctx, http.MethodPost, "/Users", u, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		// Without an id we cannot deprovision this account later by anything
		// except guesswork, so it is treated as a failure rather than a partial
		// success that looks fine until somebody leaves.
		return "", fmt.Errorf("the target created the user but returned no id, so it " +
			"could not be deprovisioned later")
	}
	return created.ID, nil
}

// SetActive turns a remote account on or off.
//
// PATCH rather than PUT. A PUT replaces the whole resource, so it silently
// erases any attribute the target holds that we do not send -- group
// memberships, profile fields, anything a local administrator set there. That
// is a destructive operation dressed up as a status change.
func (c *Client) SetActive(ctx context.Context, remoteID string, active bool) error {
	if c.target.DryRun {
		return nil
	}
	patch := map[string]any{
		"schemas": []string{schemaPatch},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": active},
		},
	}
	return c.do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(remoteID), patch, nil)
}

// DeleteUser removes a remote account.
func (c *Client) DeleteUser(ctx context.Context, remoteID string) error {
	if c.target.DryRun {
		return nil
	}
	err := c.do(ctx, http.MethodDelete, "/Users/"+url.PathEscape(remoteID), nil, nil)
	var se *Error
	if errorsAs(err, &se) && se.Status == http.StatusNotFound {
		// Already gone is the desired state. Reporting it as a failure would have
		// the queue retry forever against an account that does not exist.
		return nil
	}
	return err
}

// GetUser reads a remote account back.
//
// The whole point of verify: what we believe is in a column we wrote; what is
// true is only knowable by asking.
func (c *Client) GetUser(ctx context.Context, remoteID string) (*User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/Users/"+url.PathEscape(remoteID), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ListResponse is a SCIM list result.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Resources    []User   `json:"Resources"`
}

// FindByUserName looks up an account by userName.
//
// Used ONLY to recover from a 409 during create -- to find the id of an account
// that already exists so it can be recorded. Never used for deprovisioning: a
// userName can change, and deleting whatever currently answers to a name is how
// the wrong account gets removed.
func (c *Client) FindByUserName(ctx context.Context, userName string) (*User, error) {
	// The comparison value is a JSON string, not a Go one.
	//
	// RFC 7644 §3.4.2.2, of the filter grammar: "the `compValue` (comparison
	// value) rule is built on JSON Data Interchange format ABNF rules as
	// specified in [RFC7159]".
	//
	// This was fmt.Sprintf("userName eq %q", userName). Go's %q agrees with JSON
	// on the cases that matter for injection -- a quote becomes \" and a
	// backslash \\ either way, so a crafted userName could never break out of
	// the literal -- but it diverges on control characters, emitting Go escapes
	// that JSON does not define:
	//
	//	input          %q            JSON
	//	"bell\aname"    "bell\aname"   "bell\u0007name"
	//	"ctrl\x01name"  "ctrl\x01name" "ctrl\u0001name"
	//
	// A userName carrying one of those produced a filter the target is right to
	// reject, and the failure would look like the target misbehaving. Marshalling
	// the string is both shorter and exactly what the grammar asks for.
	quoted, err := json.Marshal(userName)
	if err != nil {
		return nil, fmt.Errorf("encoding the userName filter: %w", err)
	}
	filter := url.Values{"filter": {"userName eq " + string(quoted)}}
	var list ListResponse
	if err := c.do(ctx, http.MethodGet, "/Users?"+filter.Encode(), nil, &list); err != nil {
		return nil, err
	}
	for i := range list.Resources {
		if strings.EqualFold(list.Resources[i].UserName, userName) {
			return &list.Resources[i], nil
		}
	}
	return nil, nil
}

// ListUsers pages through every user the target holds.
func (c *Client) ListUsers(ctx context.Context, pageSize int) ([]User, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	var all []User
	start := 1
	for {
		q := url.Values{
			"startIndex": {fmt.Sprint(start)},
			"count":      {fmt.Sprint(pageSize)},
		}
		var list ListResponse
		if err := c.do(ctx, http.MethodGet, "/Users?"+q.Encode(), nil, &list); err != nil {
			return nil, err
		}
		all = append(all, list.Resources...)

		// Termination is on what came back, not on totalResults: a target that
		// reports a total it does not deliver would otherwise loop forever.
		if len(list.Resources) == 0 || len(all) >= list.TotalResults || len(list.Resources) < pageSize {
			return all, nil
		}
		start += len(list.Resources)
		if start > 100000 {
			return all, fmt.Errorf("stopped paging after 100000 users; the target is not " +
				"advancing its pages")
		}
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, into any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimSuffix(c.target.BaseURL, "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.target.Token)
	req.Header.Set("Accept", contentType)
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("calling the target: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode >= 400 {
		return &Error{
			Status:   resp.StatusCode,
			Detail:   scimErrorDetail(raw),
			Conflict: resp.StatusCode == http.StatusConflict,
		}
	}
	if into != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, into); err != nil {
			return fmt.Errorf("the target's response did not parse: %w", err)
		}
	}
	return nil
}

// scimErrorDetail pulls the human-readable part out of a SCIM error.
func scimErrorDetail(raw []byte) string {
	var e struct {
		Detail string `json:"detail"`
		Status any    `json:"status"`
	}
	if err := json.Unmarshal(raw, &e); err == nil && e.Detail != "" {
		return e.Detail
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "(no body)"
	}
	return s
}

// errorsAs is errors.As, kept local so this package's only dependency on the
// standard errors package is the one line that needs it.
func errorsAs(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
