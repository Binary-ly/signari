package signari

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The client, and specifically the property no other provider in this field can
// offer: an apply that would overwrite somebody else's change fails instead.
//
// The server half is tested in the engine (internal/adminapi). What is tested
// here is that this client SENDS the precondition correctly and reports the
// refusal as something a human can act on -- because a provider that sent a
// malformed If-Match would get an unconditional write while believing it was
// protected, which is worse than not offering the feature.

// fakeAdmin is a minimal Admin API with the same precondition semantics as the
// real one: a quoted strong entity tag, 412 on mismatch, and a version that only
// moves on a successful write.
type fakeAdmin struct {
	mu      sync.Mutex
	version int64
	enabled bool
	// writes counts successful mutations, so a test can prove a refused one wrote
	// nothing rather than trusting the status code.
	writes int
}

func (f *fakeAdmin) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(f.version, 10)))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"org_id":"org-1","display_name":"d","enabled":%t}`,
			r.PathValue("id"), f.enabled)
	})

	mux.HandleFunc("POST /admin/clients", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.version++
		f.writes++
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(f.version, 10)))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"client_id":"c","client_secret":"s3cret","config_version":%d}`, f.version)
	})

	mux.HandleFunc("PATCH /admin/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if im := r.Header.Get("If-Match"); im != "" {
			// The real server refuses a malformed tag rather than ignoring it.
			// Mirrored here so a client that sent one would fail this test rather
			// than silently getting an unconditional write.
			if len(im) < 2 || im[0] != '"' || im[len(im)-1] != '"' {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_if_match","detail":"an entity tag must be quoted"}`)
				return
			}
			want, err := strconv.ParseInt(strings.Trim(im, `"`), 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_if_match"}`)
				return
			}
			if want != f.version {
				w.WriteHeader(http.StatusPreconditionFailed)
				fmt.Fprintf(w, `{"error":"precondition_failed","expected_version":%d,"current_version":%d}`,
					want, f.version)
				return
			}
		}

		var body struct {
			Enabled *bool `json:"enabled"`
		}
		_ = decodeJSON(r, &body)
		if body.Enabled != nil {
			f.enabled = *body.Enabled
		}
		f.version++
		f.writes++
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(f.version, 10)))
		fmt.Fprintf(w, `{"client_id":%q,"config_version":%d}`, r.PathValue("id"), f.version)
	})

	return mux
}

func decodeJSON(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	return jsonDecode(r.Body, v)
}

func newFake(t *testing.T) (*fakeAdmin, *Client) {
	t.Helper()
	f := &fakeAdmin{version: 41, enabled: true}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return f, &Client{Endpoint: srv.URL, Token: "t", HTTP: srv.Client()}
}

// THE test. An update whose precondition is stale is refused, and nothing is
// written.
//
// This is the concurrent-apply hole that every other provider in this field
// lives with: plan reads, somebody else writes, apply overwrites them silently.
func TestAStaleUpdateIsRefusedAndWritesNothing(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()

	// Terraform plans against version 41...
	_, readVersion, err := c.GetClient(ctx, "app")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if readVersion != 41 {
		t.Fatalf("read version = %d, want 41", readVersion)
	}

	// ...somebody else writes in between.
	f.mu.Lock()
	f.version = 47
	f.mu.Unlock()
	writesBefore := f.writes

	// ...and the apply is refused rather than winning.
	_, err = c.SetClientEnabled(ctx, "app", false, readVersion)

	var conflict *ErrConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want ErrConflict. Without this the apply silently "+
			"overwrites whatever changed after the plan", err)
	}
	if conflict.Expected != 41 || conflict.Actual != 47 {
		t.Errorf("conflict reports expected=%d actual=%d, want 41/47",
			conflict.Expected, conflict.Actual)
	}
	if f.writes != writesBefore {
		t.Error("a refused apply still performed a write")
	}
	// The message has to send somebody to `terraform plan`, not to an RFC.
	if !strings.Contains(conflict.Error(), "plan") {
		t.Errorf("the conflict message does not tell the operator what to do: %s", conflict)
	}
}

// The unconditional path still works, because that is what an operator gets if
// they turn preconditions off -- and it is what every other provider does.
func TestAnUnconditionalUpdateSucceedsWhateverTheVersion(t *testing.T) {
	f, c := newFake(t)
	f.mu.Lock()
	f.version = 99
	f.mu.Unlock()

	if _, err := c.SetClientEnabled(context.Background(), "app", false, 0); err != nil {
		t.Fatalf("an unconditional update failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enabled {
		t.Error("the update did not apply")
	}
}

// A matching precondition applies, and returns the NEW version so the next write
// can be conditional without another read.
func TestAMatchingPreconditionAppliesAndAdvancesTheVersion(t *testing.T) {
	_, c := newFake(t)
	ctx := context.Background()

	_, v, err := c.GetClient(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.SetClientEnabled(ctx, "app", false, v)
	if err != nil {
		t.Fatalf("a matching precondition was refused: %v", err)
	}
	if res.Version <= v {
		t.Errorf("version %d -> %d: a successful write must advance it, or the next "+
			"conditional write uses a stale tag and fails", v, res.Version)
	}
}

// The If-Match header must be a QUOTED entity tag.
//
// The real server refuses an unquoted one rather than ignoring it -- correctly,
// because ignoring it would perform an unconditional write for a caller that
// asked for a conditional one. So a client that formats it wrongly gets a 400
// here rather than silently losing its protection.
func TestTheIfMatchHeaderIsAQuotedEntityTag(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("If-Match")
		w.Header().Set("ETag", `"2"`)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, err := c.SetClientEnabled(context.Background(), "app", true, 42); err != nil {
		t.Fatal(err)
	}
	if seen != `"42"` {
		t.Errorf("If-Match = %q, want %q. An unquoted tag is refused by the server, "+
			"so this would lose the protection it looks like it has", seen, `"42"`)
	}
}

// No If-Match header at all when the precondition is zero.
func TestNoHeaderIsSentWhenUnconditional(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["If-Match"]
		w.Header().Set("ETag", `"1"`)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, err := c.SetClientEnabled(context.Background(), "app", true, 0); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("an If-Match header was sent for an unconditional write")
	}
}

// A 404 is distinguishable, because Terraform turns it into "recreate" rather
// than a hard failure.
func TestAMissingClientIsReportedAsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"client_not_found"}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "t", HTTP: srv.Client()}
	if _, _, err := c.GetClient(context.Background(), "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// Other refusals carry the server's own message, because an admin API's errors
// are written for operators and losing them makes every failure look the same.
func TestAnAPIErrorCarriesTheServersMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"insufficient_scope","detail":"this token does not hold clients:write"}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL, Token: "t", HTTP: srv.Client()}
	_, err := c.SetClientEnabled(context.Background(), "app", true, 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want APIError", err)
	}
	if !strings.Contains(apiErr.Error(), "clients:write") {
		t.Errorf("the server's detail was lost: %s", apiErr)
	}
}

// Entity tag parsing, including the shapes that must yield "not conditional".
func TestParseETag(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{`"42"`, 42},
		{`W/"42"`, 42},
		{`42`, 0},
		{``, 0},
		{`"abc"`, 0},
		{`"`, 0},
	} {
		if got := parseETag(tc.in); got != tc.want {
			t.Errorf("parseETag(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
