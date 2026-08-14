package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeSCIM is a downstream application that behaves like a real SCIM target,
// including the ways real ones misbehave.
type fakeSCIM struct {
	*httptest.Server
	mu      sync.Mutex
	users   map[string]*User
	nextID  int
	patches int
	puts    int
	deletes int
	// ignorePatch reproduces the target that answers 200 and changes nothing --
	// the single most dangerous behaviour in this whole area, because every
	// local record says the deactivation succeeded.
	ignorePatch bool
}

func newFakeSCIM(t *testing.T) *fakeSCIM {
	f := &fakeSCIM{users: map[string]*User{}, nextID: 1}
	mux := http.NewServeMux()

	mux.HandleFunc("/Users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			var u User
			_ = json.NewDecoder(r.Body).Decode(&u)
			for _, e := range f.users {
				if strings.EqualFold(e.UserName, u.UserName) {
					w.Header().Set("Content-Type", contentType)
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"detail":"userName already exists","status":"409"}`))
					return
				}
			}
			u.ID = fmt.Sprintf("remote-%d", f.nextID)
			f.nextID++
			f.users[u.ID] = &u
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodGet:
			var out []User
			filter := r.URL.Query().Get("filter")
			for _, u := range f.users {
				if filter != "" && !strings.Contains(filter, u.UserName) {
					continue
				}
				out = append(out, *u)
			}
			_ = json.NewEncoder(w).Encode(ListResponse{
				Schemas: []string{schemaList}, TotalResults: len(out),
				ItemsPerPage: len(out), StartIndex: 1, Resources: out,
			})
		}
	})

	mux.HandleFunc("/Users/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/Users/")
		u, ok := f.users[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"not found","status":"404"}`))
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodPatch:
			f.patches++
			if f.ignorePatch {
				// 200, and nothing changes.
				_ = json.NewEncoder(w).Encode(u)
				return
			}
			var p struct {
				Operations []struct {
					Op    string `json:"op"`
					Path  string `json:"path"`
					Value any    `json:"value"`
				} `json:"Operations"`
			}
			_ = json.NewDecoder(r.Body).Decode(&p)
			for _, op := range p.Operations {
				if op.Path == "active" {
					if b, ok := op.Value.(bool); ok {
						u.Active = b
					}
				}
			}
			_ = json.NewEncoder(w).Encode(u)
		case http.MethodPut:
			f.puts++
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			f.deletes++
			delete(f.users, id)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeSCIM) client() *Client {
	return NewClient(Target{Slug: "fake", BaseURL: f.Server.URL, Token: "tok"}, f.Server.Client())
}

func TestCreateAndReadBack(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	id, err := c.CreateUser(ctx, NewUser("local-1", "alice@example.com", "Alice", "alice@example.com", true))
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("no remote id returned")
	}
	u, err := c.GetUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.UserName != "alice@example.com" || !u.Active || u.ExternalID != "local-1" {
		t.Errorf("read back %+v", u)
	}
}

// TestDeactivateUsesPatchNotPut.
//
// PUT replaces the whole resource, so it erases every attribute the target
// holds that we did not send -- group memberships, profile fields, anything a
// local administrator set. Turning somebody off must not also wipe their record.
func TestDeactivateUsesPatchNotPut(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	id, _ := c.CreateUser(ctx, NewUser("local-1", "bob@example.com", "Bob", "bob@example.com", true))
	if err := c.SetActive(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if f.puts != 0 {
		t.Errorf("used PUT %d time(s); a full replace erases attributes we do not send", f.puts)
	}
	if f.patches != 1 {
		t.Errorf("patches = %d, want 1", f.patches)
	}
	u, _ := c.GetUser(ctx, id)
	if u.Active {
		t.Error("the account is still active after deactivation")
	}
}

// TestConflictIsDistinguishable. A 409 on create means the account exists; a
// caller must be able to tell that from a real failure so it can find the id
// rather than retrying forever.
func TestConflictIsDistinguishable(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	u := NewUser("local-1", "carol@example.com", "Carol", "carol@example.com", true)
	if _, err := c.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	_, err := c.CreateUser(ctx, u)
	if err == nil {
		t.Fatal("a duplicate create succeeded")
	}
	var se *Error
	if !errorsAs(err, &se) || !se.Conflict {
		t.Fatalf("error is not marked as a conflict: %v", err)
	}
	if se.Retryable() {
		t.Error("a conflict is marked retryable; the queue would retry it forever")
	}

	// And the caller can recover the existing id.
	found, err := c.FindByUserName(ctx, "carol@example.com")
	if err != nil || found == nil {
		t.Fatalf("could not find the existing account: %v", err)
	}
}

func TestRetryableDistinguishesClientAndServerFaults(t *testing.T) {
	cases := []struct {
		status    int
		retryable bool
	}{
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusConflict, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
	}
	for _, c := range cases {
		e := &Error{Status: c.status}
		if e.Retryable() != c.retryable {
			t.Errorf("status %d: Retryable() = %v, want %v -- retrying a permanent "+
				"failure hides the real problem behind a growing backlog",
				c.status, e.Retryable(), c.retryable)
		}
	}
}

// TestDeleteOfAMissingAccountSucceeds. Already gone is the desired state;
// treating it as failure has the queue retry against nothing, forever.
func TestDeleteOfAMissingAccountSucceeds(t *testing.T) {
	f := newFakeSCIM(t)
	if err := f.client().DeleteUser(context.Background(), "remote-does-not-exist"); err != nil {
		t.Fatalf("deleting an account that is already gone returned an error: %v", err)
	}
}

// TestVerifyCatchesTheTargetThatIgnoredTheDeactivation.
//
// The whole reason this package has a verify step. The target answers 200, our
// records say the user is deactivated, and the account is still live. Nothing in
// our own tables can reveal this -- only asking the target can.
func TestVerifyCatchesTheTargetThatIgnoredTheDeactivation(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	id, _ := c.CreateUser(ctx, NewUser("local-1", "dave@example.com", "Dave", "dave@example.com", true))

	// The target now silently ignores patches.
	f.ignorePatch = true
	if err := c.SetActive(ctx, id, false); err != nil {
		t.Fatalf("the target reported failure; this test needs it to report SUCCESS: %v", err)
	}

	rep, err := Verify(ctx, c, []Expected{
		{UserID: "local-1", RemoteID: id, UserName: "dave@example.com", Active: false, Synced: true},
	}, f.Server.Client())
	if err != nil {
		t.Fatal(err)
	}

	crit := rep.CriticalFindings()
	if len(crit) != 1 {
		t.Fatalf("critical findings = %d, want 1. The account is live for somebody who "+
			"was deactivated and nothing reported it.\n%+v", len(crit), rep.Findings)
	}
	if !strings.Contains(crit[0].Summary, "STILL ACTIVE") {
		t.Errorf("summary = %q", crit[0].Summary)
	}
	if crit[0].Fix == "" {
		t.Error("a critical finding with no stated fix")
	}
}

// TestVerifyIsQuietWhenEverythingAgrees. A checker that always finds something
// gets ignored, and then the real finding is ignored too.
func TestVerifyIsQuietWhenEverythingAgrees(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	active, _ := c.CreateUser(ctx, NewUser("l1", "eve@example.com", "Eve", "eve@example.com", true))
	gone, _ := c.CreateUser(ctx, NewUser("l2", "mallory@example.com", "M", "m@example.com", true))
	if err := c.DeleteUser(ctx, gone); err != nil {
		t.Fatal(err)
	}

	rep, _ := Verify(ctx, c, []Expected{
		{UserID: "l1", RemoteID: active, UserName: "eve@example.com", Active: true, Synced: true},
		{UserID: "l2", RemoteID: gone, UserName: "mallory@example.com", Active: false, Synced: true},
	}, f.Server.Client())

	if len(rep.Findings) != 0 {
		t.Errorf("found %d issue(s) when everything agrees: %+v", len(rep.Findings), rep.Findings)
	}
	if !strings.Contains(rep.Summary(), "no drift") {
		t.Errorf("summary = %q", rep.Summary())
	}
}

// TestVerifyReportsMissingAccessAsAWarningNotCritical. Somebody unable to work
// is urgent; it is not a security failure, and conflating the two buries the
// findings that are.
func TestVerifyReportsMissingAccessAsAWarningNotCritical(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	rep, _ := Verify(ctx, c, []Expected{
		{UserID: "l1", RemoteID: "never-created", UserName: "frank@example.com", Active: true, Synced: true},
	}, f.Server.Client())

	if len(rep.CriticalFindings()) != 0 {
		t.Error("a missing account was reported as critical")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != Warning {
		t.Fatalf("findings = %+v", rep.Findings)
	}
}

// TestVerifyDoesNotTreatUnknownRemoteAccountsAsDrift.
//
// A target legitimately holds accounts we did not create -- service accounts,
// people who predate the integration. Reporting them as drift invites somebody
// to "clean up", and a provisioning integration that deletes what it does not
// recognise is a way to destroy a production service account.
func TestVerifyDoesNotTreatUnknownRemoteAccountsAsDrift(t *testing.T) {
	f := newFakeSCIM(t)
	c := f.client()
	ctx := context.Background()

	_, _ = c.CreateUser(ctx, NewUser("", "service-account", "svc", "", true))

	rep, _ := Verify(ctx, c, nil, f.Server.Client())
	if len(rep.CriticalFindings()) != 0 {
		t.Error("an unrecognised remote account was reported as critical")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != Info {
		t.Fatalf("findings = %+v, want one info finding", rep.Findings)
	}
	if !strings.Contains(rep.Findings[0].Fix, "left alone") {
		t.Errorf("the fix should say we deliberately did not touch it; got %q", rep.Findings[0].Fix)
	}
}

// TestVerifyReportsAnUnreachableTargetRatherThanFailing.
//
// "I could not check" and "everything is fine" must never be the same answer.
func TestVerifyReportsAnUnreachableTargetRatherThanFailing(t *testing.T) {
	c := NewClient(Target{Slug: "down", BaseURL: "https://127.0.0.1:1", Token: "t"}, nil)
	rep, err := Verify(context.Background(), c, []Expected{
		{RemoteID: "x", Active: false},
	}, nil)
	if err != nil {
		t.Fatalf("Verify returned an error instead of reporting the target unreachable: %v", err)
	}
	if !rep.Unreachable {
		t.Fatal("an unreachable target was not marked unreachable")
	}
	if !strings.Contains(rep.Summary(), "UNREACHABLE") {
		t.Errorf("summary = %q", rep.Summary())
	}
}

// TestDryRunSendsNothing.
func TestDryRunSendsNothing(t *testing.T) {
	f := newFakeSCIM(t)
	c := NewClient(Target{Slug: "fake", BaseURL: f.Server.URL, Token: "tok", DryRun: true}, f.Server.Client())
	ctx := context.Background()

	if _, err := c.CreateUser(ctx, NewUser("l1", "x@example.com", "X", "x@example.com", true)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetActive(ctx, "remote-1", false); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, "remote-1"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.users) != 0 || f.patches != 0 || f.deletes != 0 {
		t.Errorf("dry run touched the target: %d users, %d patches, %d deletes",
			len(f.users), f.patches, f.deletes)
	}
}

// TestListPagesToCompletion, and terminates even when the target lies about
// how many results there are.
func TestListPagesToCompletion(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Claims 1000 results and returns one page, forever.
		_ = json.NewEncoder(w).Encode(ListResponse{
			TotalResults: 1000, ItemsPerPage: 1, StartIndex: 1,
			Resources: []User{{ID: fmt.Sprintf("u%d", calls), UserName: "x"}},
		})
	}))
	defer srv.Close()

	c := NewClient(Target{Slug: "liar", BaseURL: srv.URL, Token: "t"}, srv.Client())
	users, err := c.ListUsers(context.Background(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// One short page means the end, regardless of the claimed total.
	if len(users) != 1 {
		t.Errorf("read %d users from a target returning short pages", len(users))
	}
}
