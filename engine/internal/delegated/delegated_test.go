package delegated

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The distinction this package exists to get right: "your password is wrong" and
// "we could not ask" are different answers, and conflating them is how an outage
// at the OLD provider becomes every user in the organisation being told they
// typed their password wrong -- and, worse, being throttled for it.
func TestRejectedAndUnavailableAreDistinguished(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{"wrong password", 400, `{"error":"invalid_grant"}`, ErrRejected},
		{"unauthorised", 401, `{"error":"invalid_grant"}`, ErrRejected},

		// OUR misconfiguration, not the user's fault.
		{"our client is wrong", 401, `{"error":"invalid_client"}`, ErrUnavailable},
		{"grant not enabled at source", 400, `{"error":"unsupported_grant_type"}`, ErrUnavailable},

		{"source is down", 503, ``, ErrUnavailable},
		{"source rate limited us", 429, ``, ErrUnavailable},

		// A 200 with no access token is not an acceptance, however friendly it
		// looks. Some gateways answer 200 with an error body.
		{"200 with an error body", 200, `{"error":"invalid_grant"}`, ErrRejected},
		{"200 with no token at all", 200, `{"ok":true}`, ErrRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			v := &Verifier{client: srv.Client()}
			err := v.Verify(context.Background(),
				Source{Kind: "oidc_password", TokenEndpoint: srv.URL, ClientID: "c"},
				"alice", "pw")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAcceptedWhenTheSourceIssuesAToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		// The credential must actually be forwarded, in the shape the old
		// provider expects.
		if r.PostForm.Get("grant_type") != "password" ||
			r.PostForm.Get("username") != "alice" ||
			r.PostForm.Get("password") != "pw" {
			t.Errorf("unexpected form: %v", r.PostForm)
		}
		_, _ = w.Write([]byte(`{"access_token":"abc","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	v := &Verifier{client: srv.Client()}
	if err := v.Verify(context.Background(),
		Source{Kind: "oidc_password", TokenEndpoint: srv.URL, ClientID: "c", Scope: "openid"},
		"alice", "pw"); err != nil {
		t.Fatalf("a valid credential was not accepted: %v", err)
	}
}

// Forwarding a password over plaintext hands it to anyone on the path. Refused
// here rather than only at configuration time, so a source edited directly in
// the database cannot downgrade the transport.
func TestPlaintextEndpointIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the password was forwarded over plaintext")
		_, _ = w.Write([]byte(`{"access_token":"abc"}`))
	}))
	defer srv.Close()

	v := New()
	err := v.Verify(context.Background(),
		Source{Kind: "oidc_password", TokenEndpoint: srv.URL, ClientID: "c"}, "alice", "pw")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("plaintext endpoint was used: %v", err)
	}
}

// A token endpoint does not redirect. Following one would forward the user's
// password to wherever the redirect pointed.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked bool
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
		_, _ = w.Write([]byte(`{"access_token":"abc"}`))
	}))
	defer sink.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	// The server's own client, with OUR redirect policy applied. Using the bare
	// httptest client would test nothing: it has no CheckRedirect, so the
	// "protection" under test would not even be in the path.
	c := srv.Client()
	c.CheckRedirect = New().client.CheckRedirect
	v := &Verifier{client: c}

	err := v.Verify(context.Background(),
		Source{Kind: "oidc_password", TokenEndpoint: srv.URL, ClientID: "c"}, "alice", "pw")
	if leaked {
		t.Fatal("the password was forwarded to a redirect target")
	}
	if err == nil {
		t.Fatal("a redirect was treated as a successful verification")
	}
}

// A hostile or broken endpoint must not be able to exhaust memory on the login
// path.
func TestOversizedResponseIsBounded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		big := strings.Repeat("x", 1<<20)
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte(big))
		}
	}))
	defer srv.Close()

	v := &Verifier{client: srv.Client()}
	if err := v.Verify(context.Background(),
		Source{Kind: "oidc_password", TokenEndpoint: srv.URL, ClientID: "c"}, "alice", "pw"); err == nil {
		t.Fatal("a 64MB junk response was treated as success")
	}
}
