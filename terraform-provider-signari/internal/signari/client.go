// Package signari is the Admin API client the Terraform provider uses.
//
// # Why this provider is different from every other one in this field
//
// Terraform's read-modify-write cycle has a hole in it that everybody lives
// with. `plan` reads the world, a human reads the plan, `apply` writes it -- and
// between the read and the write, anything may have changed. Another apply from
// a colleague, a CI pipeline, somebody in the console. Terraform detects nothing:
// it sends the update, the server takes it, and the other change is gone.
//
// The usual mitigations are all outside the API: state locking (protects the
// STATE file, not the server), `-refresh=true` (narrows the window, never closes
// it), and telling people not to touch the console.
//
// This provider closes it, because the API it talks to supports RFC 7232
// preconditions. Every read records the configuration version; every write sends
// it back as If-Match. If anything moved in between, the server refuses with 412
// and Terraform reports a conflict instead of silently winning.
//
// That is only possible because the server offers it. Surveyed on 25 August 2026
// against current upstream source, the comparable admin APIs in this field are
// last-write-wins: no If-Match handling, and no precondition field on any write
// message. A provider for one of those cannot offer this no matter how it is
// written.
package signari

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the Signari Admin API.
type Client struct {
	// Endpoint is the admin API's base URL, without a trailing slash.
	Endpoint string
	// Token is the bearer credential from `signari admin-token create`.
	Token string
	// HTTP is the transport. Supplied so a test can provide its own; nil means a
	// client with a sane timeout.
	HTTP *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ErrConflict is a refused precondition: the configuration moved between this
// caller's read and its write.
//
// The whole reason this package exists. A provider that could not distinguish
// this from a generic failure would have to retry blindly, which is the
// clobbering behaviour again with extra steps.
type ErrConflict struct {
	Expected int64
	Actual   int64
}

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("the Signari configuration changed while this apply was "+
		"planned: it was at version %d when read, and is now at %d. Something else "+
		"has written since -- another apply, a pipeline, or somebody in the console. "+
		"Nothing was changed. Re-run `terraform plan` to see the current state",
		e.Expected, e.Actual)
}

// ErrNotFound is a 404, which Terraform turns into "removed outside Terraform".
var ErrNotFound = errors.New("not found")

// APIError is any other refusal, carrying the server's own message.
type APIError struct {
	Status int
	Code   string
	Detail string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Detail)
	}
	return fmt.Sprintf("%s (%d)", e.Code, e.Status)
}

// Result carries a response body and the version it was observed at.
type Result struct {
	Body []byte
	// Version is the ETag the server returned, as an integer. Threaded into
	// Terraform state so the NEXT write can be conditional on it.
	Version int64
}

// do performs one request, optionally conditional.
//
// ifMatch of 0 means unconditional. That is used for creates, where there is no
// prior read to be conditional on.
func (c *Client) do(ctx context.Context, method, path string, body any, ifMatch int64) (*Result, error) {
	var rdr io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding the request: %w", err)
		}
		rdr = bytes.NewReader(blob)
	}

	req, err := http.NewRequestWithContext(ctx, method,
		strings.TrimSuffix(c.Endpoint, "/")+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifMatch > 0 {
		// The precondition. Quoted, because RFC 7232 entity tags are quoted and
		// the server refuses an unquoted one rather than ignoring it -- which is
		// the correct behaviour and the reason this is worth getting right.
		req.Header.Set("If-Match", fmt.Sprintf("%q", fmt.Sprint(ifMatch)))
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	blob, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusPreconditionFailed:
		var pf struct {
			Expected int64 `json:"expected_version"`
			Current  int64 `json:"current_version"`
		}
		_ = json.Unmarshal(blob, &pf)
		return nil, &ErrConflict{Expected: pf.Expected, Actual: pf.Current}
	case resp.StatusCode >= 400:
		var e struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(blob, &e)
		if e.Error == "" {
			e.Error = "unexpected_status"
		}
		return nil, &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
	}

	return &Result{Body: blob, Version: parseETag(resp.Header.Get("ETag"))}, nil
}

// parseETag reads the version out of a strong entity tag.
//
// A missing or unparseable tag yields 0, which means "not conditional". Failing
// closed here would be wrong in a specific way: it would make this provider
// unusable against a server that simply does not send the header, when the
// correct behaviour is the one every other provider in the world has.
func parseETag(tag string) int64 {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return 0
	}
	var v int64
	if _, err := fmt.Sscanf(tag[1:len(tag)-1], "%d", &v); err != nil {
		return 0
	}
	return v
}

// ClientResource is an OAuth client as this provider models it.
type ClientResource struct {
	ClientID     string   `json:"client_id"`
	OrgID        string   `json:"org_id,omitempty"`
	DisplayName  string   `json:"display_name,omitempty"`
	Public       bool     `json:"public,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Enabled      bool     `json:"enabled"`
}

// CreateClient registers a client. Unconditional: there is nothing to be
// conditional on before a resource exists.
func (c *Client) CreateClient(ctx context.Context, in ClientResource) (*Result, error) {
	return c.do(ctx, http.MethodPost, "/admin/clients", in, 0)
}

// GetClient reads one, returning the version it was read at.
func (c *Client) GetClient(ctx context.Context, clientID string) (*ClientResource, int64, error) {
	res, err := c.do(ctx, http.MethodGet, "/admin/clients/"+clientID, nil, 0)
	if err != nil {
		return nil, 0, err
	}
	var out ClientResource
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return nil, 0, fmt.Errorf("decoding the client: %w", err)
	}
	return &out, res.Version, nil
}

// SetClientEnabled updates a client, conditional on the version it was read at.
//
// ifMatch comes from Terraform state, recorded by the last Read. Passing 0 makes
// the write unconditional, which is what an operator gets if they disable the
// feature -- and is the behaviour every other provider in this field has.
func (c *Client) SetClientEnabled(ctx context.Context, clientID string, enabled bool, ifMatch int64) (*Result, error) {
	return c.do(ctx, http.MethodPatch, "/admin/clients/"+clientID,
		map[string]any{"enabled": enabled}, ifMatch)
}

// jsonDecode is a small indirection so the test's fake server can decode a body
// without importing encoding/json separately.
func jsonDecode(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }
