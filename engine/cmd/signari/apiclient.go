package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"signari.dev/engine/internal/safedial"
)

// The Admin API from the command line (6.16). `signari api` sends one request
// to any route, and the commands with an endpoint mode make their change
// through the API when given -admin-url. Either way the change is the API's: a
// token it audits under its own id, refused what its scopes and roles do not
// allow, with no database credentials on the machine it runs from. Before,
// every command needed a DSN.

// apiClient calls one Admin API with one bearer token.
type apiClient struct {
	base  *url.URL
	token string
	hc    *http.Client
}

// newAPIClient is the client -admin-url (or SIGNARI_ADMIN_URL) and the token
// in SIGNARI_ADMIN_TOKEN or -token-file describe. The token is never taken as
// a flag's value, which a process listing and a shell's history would keep.
func newAPIClient(adminURL, tokenFile string) (*apiClient, error) {
	if adminURL == "" {
		adminURL = os.Getenv("SIGNARI_ADMIN_URL")
	}
	if adminURL == "" {
		return nil, usageError{errors.New("give -admin-url, the Admin API's address, or set SIGNARI_ADMIN_URL")}
	}
	u, err := url.Parse(strings.TrimRight(adminURL, "/"))
	if err != nil || u.Host == "" {
		return nil, usageError{fmt.Errorf("-admin-url %q is not an address like https://admin.example.com:8443", adminURL)}
	}
	switch u.Scheme {
	case "https":
	case "http":
		// The bearer token is the credential; plaintext only where it does
		// not cross a network, as the listener allows it only by name.
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, usageError{fmt.Errorf("-admin-url %s is plaintext http to another host, which would send the "+
				"admin token in the clear; use https", adminURL)}
		}
	default:
		return nil, usageError{fmt.Errorf("-admin-url must be https, not %q", u.Scheme)}
	}
	token := os.Getenv("SIGNARI_ADMIN_TOKEN")
	if tokenFile != "" {
		raw, err := os.ReadFile(tokenFile) // #nosec G304 -- the operator names the file
		if err != nil {
			return nil, fmt.Errorf("reading -token-file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return nil, usageError{errors.New("set SIGNARI_ADMIN_TOKEN to an admin token, or give -token-file")}
	}
	return &apiClient{base: u, token: token, hc: &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: safedial.Roots(), MinVersion: tls.VersionTLS12},
		},
		// A redirect would carry the token somewhere the operator did not name.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// apiResponse is what the API answered.
type apiResponse struct {
	Status int
	ETag   string
	Body   []byte
}

// apiError is a refusal from the API, which says what it refused and why.
type apiError struct {
	Status int
	Code   string
	Detail string
}

func (e apiError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("the Admin API answered %d %s: %s", e.Status, e.Code, e.Detail)
	}
	return fmt.Sprintf("the Admin API answered %d %s", e.Status, e.Code)
}

// do sends one request. A 4xx or 5xx is an apiError carrying the API's own
// error code; the body is still returned.
func (c *apiClient) do(ctx context.Context, method, path string, body []byte, ifMatch string) (*apiResponse, error) {
	if !strings.HasPrefix(path, "/admin/") {
		return nil, usageError{fmt.Errorf("the path %q is not an Admin API route; they start /admin/", path)}
	}
	target := *c.base
	rel, err := url.Parse(path)
	if err != nil {
		return nil, usageError{fmt.Errorf("the path %q does not parse: %w", path, err)}
	}
	target.Path = strings.TrimRight(c.base.Path, "/") + rel.Path
	target.RawQuery = rel.RawQuery
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		if !strings.HasPrefix(ifMatch, `"`) && ifMatch != "*" {
			ifMatch = `"` + ifMatch + `"`
		}
		req.Header.Set("If-Match", ifMatch)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling the Admin API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the Admin API's answer: %w", err)
	}
	out := &apiResponse{Status: resp.StatusCode, ETag: resp.Header.Get("ETag"), Body: raw}
	if resp.StatusCode >= 400 {
		var e struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return out, apiError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
	}
	return out, nil
}

// call is do with a JSON body made from v, decoding the answer into into.
func (c *apiClient) call(ctx context.Context, method, path string, v, into any) error {
	var body []byte
	if v != nil {
		var err error
		if body, err = json.Marshal(v); err != nil {
			return err
		}
	}
	resp, err := c.do(ctx, method, path, body, "")
	if err != nil {
		return err
	}
	if into != nil && len(resp.Body) > 0 {
		return json.Unmarshal(resp.Body, into)
	}
	return nil
}

// apiCommand is `signari api <METHOD> <path> [-data JSON|@file|-] [-if-match
// N] [-admin-url URL] [-token-file FILE]`: one request to any route, its
// answer printed as the API sent it.
func apiCommand(registry *flag.FlagSet, args []string, data, ifMatch, adminURL, tokenFile *string,
	timeout *time.Duration) error {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return usageError{errors.New("give the method and the path: signari api GET /admin/me")}
	}
	method, path := strings.ToUpper(args[0]), args[1]
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return usageError{fmt.Errorf("%q is not a method the Admin API answers: GET, POST, PUT, PATCH or DELETE", args[0])}
	}
	fs := flag.NewFlagSet("signari api", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, n := range []string{"data", "if-match", "admin-url", "token-file", "timeout"} {
		f := registry.Lookup(n)
		fs.Var(f.Value, f.Name, f.Usage)
	}
	if err := fs.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandHelp(os.Stdout, "api", fs)
			return nil
		}
		return usageError{fmt.Errorf("%w; `signari help api` lists the flags it takes", err)}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Errorf("signari api takes a method, a path and flags, and %q is none of them", fs.Arg(0))}
	}
	var body []byte
	switch d := *data; {
	case d == "":
	case d == "-":
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
		if err != nil {
			return err
		}
		body = raw
	case strings.HasPrefix(d, "@"):
		raw, err := os.ReadFile(d[1:]) // #nosec G304 -- the operator names the file
		if err != nil {
			return fmt.Errorf("reading -data: %w", err)
		}
		body = raw
	default:
		body = []byte(d)
	}
	if body != nil && !json.Valid(body) {
		return usageError{errors.New("-data is not JSON")}
	}
	c, err := newAPIClient(*adminURL, *tokenFile)
	if err != nil {
		return err
	}
	runFor := *timeout
	if runFor == 0 {
		runFor = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), runFor)
	defer cancel()
	resp, err := c.do(ctx, method, path, body, *ifMatch)
	if resp != nil {
		printAPIBody(os.Stdout, resp.Body)
	}
	return err
}

// printAPIBody prints a JSON answer indented, and anything else as it came.
func printAPIBody(w io.Writer, body []byte) {
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		pretty.WriteByte('\n')
		_, _ = w.Write(pretty.Bytes())
		return
	}
	_, _ = w.Write(body)
}
