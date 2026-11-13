package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/provision"
	"signari.dev/engine/internal/scim"
)

// scimAuthorize has somebody sign in at a target that takes the authorization code
// grant and agree, and keeps the refresh token that leaves (7.14).
//
// The code comes back to a loopback port this command opens for the one request and
// closes after, as OAuth 2.1 has a native application do
// (specs/draft-ietf-oauth-v2-1-17.txt:4375-4387 and 4597-4601): a port the system
// gives unless -redirect names one, which the target must allow, and "MUST allow
// any port" for a loopback address (:4403-4406). A target that sends people only
// to https is given that address with -redirect, and the address the browser
// arrives at is pasted here instead, whether or not anything answered there.
func scimAuthorize(ctx context.Context, conn *pgx.Conn, orgID, slug, redirect string, in io.Reader,
	out io.Writer) error {
	switch {
	case orgID == "":
		return fmt.Errorf("give -org, the organisation uuid")
	case slug == "":
		return fmt.Errorf("give -slug, the target to authorize")
	}
	root, err := rootKey()
	if err != nil {
		return err
	}
	hc, err := scimHTTPClient()
	if err != nil {
		return err
	}

	var listener net.Listener
	callback := "/callback"
	switch u, perr := url.Parse(redirect); {
	case redirect == "":
		if listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			return fmt.Errorf("opening a loopback port for the target to send you back to: %w", err)
		}
		redirect = "http://" + listener.Addr().String() + callback
	case perr == nil && u.Scheme == "http" && scim.Loopback(u):
		if u.Port() == "" {
			return fmt.Errorf("give -redirect a port: http://%s:<port>%s", u.Hostname(), u.Path)
		}
		if listener, err = net.Listen("tcp", u.Host); err != nil {
			return fmt.Errorf("opening %s for the target to send you back to: %w", u.Host, err)
		}
		if callback = u.Path; callback == "" {
			callback = "/"
		}
	}
	if listener != nil {
		defer func() { _ = listener.Close() }()
	}

	started, err := provision.BeginAuthorization(ctx, conn, root, orgID, slug, redirect)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "Open this in a browser, sign in at the target as somebody who may administer it, "+
		"and agree:\n\n  %s\n\n", started.URL)
	wait, cancel := context.WithDeadline(ctx, started.Until)
	defer cancel()
	var code string
	if listener != nil {
		_, _ = fmt.Fprintf(out, "Waiting for the target to send you back to %s, until %s.\n", redirect,
			started.Until.Format(time.TimeOnly))
		code, err = awaitCode(wait, listener, callback, started.State)
	} else {
		_, _ = fmt.Fprintf(out, "The target sends you back to %s. Paste the address your browser shows when it "+
			"gets there, whatever the page says:\n", redirect)
		code, err = pastedCode(wait, in, started.State)
	}
	if err != nil {
		return err
	}

	grant, err := provision.ExchangeAuthorization(ctx, conn, root, hc, orgID, slug, started.State, code)
	if err != nil {
		return err
	}
	at, err := grant.Keep(ctx, conn)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "authorized %s at %s\n  Each sync now asks the target for an access token with the "+
		"refresh token this left, and keeps the one it is given back.\n", slug, at.UTC().Format(time.RFC3339))
	return nil
}

// errStrayRequest is a request to the callback that is not the answer to this
// authorization: another program on the loopback interface, or an old tab.
var errStrayRequest = errors.New("that is not the answer to this authorization: its state is not the one sent")

// codeFrom is the code a redirect carries, if it answers the authorization started
// with state. An error the target sent back instead is said as it said it
// (specs/rfc6749.txt:1487-1530).
func codeFrom(q url.Values, state string) (string, error) {
	if q.Get("state") != state {
		return "", errStrayRequest
	}
	if e := q.Get("error"); e != "" {
		if d := q.Get("error_description"); d != "" {
			e += ": " + d
		}
		return "", fmt.Errorf("the target did not authorize it: %s", e)
	}
	code := q.Get("code")
	if code == "" {
		return "", errors.New("the target sent you back with no code")
	}
	return code, nil
}

// awaitCode serves the loopback callback until the answer to this authorization
// arrives or ctx ends, answering anything else as not this one.
func awaitCode(ctx context.Context, l net.Listener, callback, state string) (string, error) {
	type answer struct {
		code string
		err  error
	}
	got := make(chan answer, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path != callback {
				http.NotFound(w, r)
				return
			}
			// Nothing the request carried is written back: what the target said
			// goes to the terminal, and the page says only where to look.
			code, err := codeFrom(r.URL.Query(), state)
			if errors.Is(err, errStrayRequest) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "This is not the answer to the authorization the terminal is waiting for.\n")
				return
			}
			select {
			case got <- answer{code, err}:
			default:
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, "this authorization has already been answered\n")
				return
			}
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "The target did not authorize it. The terminal says why.\n")
				return
			}
			_, _ = io.WriteString(w, "Done. Close this window; the terminal says whether it worked.\n")
		})}
	go func() { _ = srv.Serve(l) }()
	defer func() {
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	select {
	case a := <-got:
		return a.code, a.err
	case <-ctx.Done():
		return "", fmt.Errorf("nobody came back from the target before the authorization expired: %w", ctx.Err())
	}
}

// pastedCode reads the address the browser arrived at.
func pastedCode(ctx context.Context, in io.Reader, state string) (string, error) {
	type answer struct {
		code string
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			got <- answer{"", fmt.Errorf("reading the address: %w", err)}
			return
		}
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil {
			got <- answer{"", fmt.Errorf("that is not an address: %w", err)}
			return
		}
		code, err := codeFrom(u.Query(), state)
		got <- answer{code, err}
	}()
	select {
	case a := <-got:
		return a.code, a.err
	case <-ctx.Done():
		return "", fmt.Errorf("no address was pasted before the authorization expired: %w", ctx.Err())
	}
}
