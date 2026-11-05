// Package admin is the operator's Admin API client: the one route it uses, the
// configuration file's plan and apply (docs/admin-api.md,
// POST /admin/organizations/{orgID}/config).
package admin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Change is one line of a plan.
type Change struct {
	Action      string `json:"action"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Detail      string `json:"detail"`
	Destructive bool   `json:"destructive"`
}

// Minted is a secret an apply made, answered once and never again.
type Minted struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// Result is the route's answer, to a plan or an apply.
type Result struct {
	DryRun        bool     `json:"dry_run"`
	Changes       []Change `json:"changes"`
	Create        int      `json:"create"`
	Update        int      `json:"update"`
	Delete        int      `json:"delete"`
	ConfigVersion int64    `json:"config_version"`
	Minted        []Minted `json:"minted"`
}

// ErrMoved is an apply refused because the deployment's configuration changed
// after it was planned (412): plan again.
var ErrMoved = errors.New("the configuration changed after it was planned")

// Error is any other refusal, with the route's own error code.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("%d %s", e.Status, e.Code)
}

// Client plans and applies one organisation's file.
type Client interface {
	Plan(ctx context.Context, org, document string, prune bool) (*Result, error)
	Apply(ctx context.Context, org, document string, prune bool, planned int64) (*Result, error)
}

// New is the client for an endpoint, a token, and the CA that issued the endpoint's
// certificate when it is not one the system trusts.
func New(endpoint, token string, caPEM []byte) (Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("the Admin API endpoint %q is not an http or https URL", endpoint)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the CA Secret holds no certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &client{base: strings.TrimRight(endpoint, "/"), token: token,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, nil
}

type client struct {
	base, token string
	http        *http.Client
}

func (c *client) Plan(ctx context.Context, org, document string, prune bool) (*Result, error) {
	return c.post(ctx, org, document, prune, true, 0)
}

// Apply applies the file as it was planned: the planned version goes as If-Match,
// so an apply over a deployment that moved since is refused rather than applying a
// plan nobody saw (RFC 7232; the Terraform provider sends it the same way).
func (c *client) Apply(ctx context.Context, org, document string, prune bool, planned int64) (*Result, error) {
	return c.post(ctx, org, document, prune, false, planned)
}

func (c *client) post(ctx context.Context, org, document string, prune, dryRun bool, ifMatch int64) (*Result, error) {
	body, err := json.Marshal(map[string]any{"document": document, "prune": prune, "dry_run": dryRun})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/admin/organizations/"+url.PathEscape(org)+"/config", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	if !dryRun {
		req.Header.Set("If-Match", fmt.Sprintf("%q", fmt.Sprint(ifMatch)))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed:
		return nil, ErrMoved
	case resp.StatusCode != http.StatusOK:
		// The route answers {"error": code, "detail": why} (adminapi/configapply.go).
		var e struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		return nil, &Error{Status: resp.StatusCode, Code: e.Error, Description: e.Detail}
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("reading the Admin API's answer: %w", err)
	}
	return &r, nil
}
