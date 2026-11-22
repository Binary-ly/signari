package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/outpost"
	"signari.dev/engine/internal/store"
)

// The address a bind reached an outpost from gets to the core (8.31). Without it nobody
// behind an outpost had the per-address budget the engine's own listener gives every
// client, so one host could guess for as long as it kept changing usernames, spending
// what the whole outpost may ask.
func TestAnOutpostPassesOnWhereABindCameFrom(t *testing.T) {
	f := newSignInFixture(t)
	clearOfWindowEdge(t, signInPerIPWindow)
	ctx := context.Background()
	n := time.Now().UnixNano()
	name := fmt.Sprintf("origin-%d", n)
	_, token, err := store.CreateOutpost(ctx, f.pool, f.orgID, name, "ldap", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.RemoveOutpost(context.Background(), f.pool, f.orgID, name) })
	core := httptest.NewServer(f.srv.Routes())
	t.Cleanup(core.Close)
	client, err := outpost.New(core.URL, token, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	guesser := fmt.Sprintf("198.18.%d.%d", (n>>8)&255, n&255)
	neighbour := fmt.Sprintf("198.19.%d.%d", (n>>8)&255, n&255)
	try := func(from string, i int) error {
		_, err := client.Authenticate(ldapd.WithPeerAddr(ctx, from), fmt.Sprintf("nobody-%d-%d", n, i), "wrong")
		return err
	}
	var spent bool
	for i := 0; i <= signInPerIPLimit; i++ {
		err := try(guesser, i)
		if errors.Is(err, ldapd.ErrBusy) {
			spent = i == signInPerIPLimit
			if !spent {
				t.Errorf("refused after %d guesses; the budget is %d", i, signInPerIPLimit)
			}
			break
		}
		if !errors.Is(err, outpost.ErrRefused) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if !spent {
		t.Errorf("%d different usernames from one address were never refused as a budget spent", signInPerIPLimit+1)
	}
	if err := try(neighbour, 0); !errors.Is(err, outpost.ErrRefused) {
		t.Errorf("somebody else behind the same outpost got %v; the budget is the address's", err)
	}

	// What an outpost says is read as an address or not at all.
	req, _ := http.NewRequest(http.MethodPost, core.URL+"/outpost/authenticate", bytes.NewReader([]byte(
		`{"username":"nobody","password":"wrong","client_ip":"not' an address"}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an address that is not one gave %d, want a refused password", resp.StatusCode)
	}

	// Each call says what it was made by, and the core keeps it for the operator.
	client.Identify("1.2.3")
	if err := client.Check(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	version := ""
	for version == "" && time.Now().Before(deadline) {
		got, err := store.Outposts(ctx, f.pool, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range got {
			if o.Name == name {
				version = o.Version
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if version != "1.2.3" {
		t.Errorf("the core recorded version %q", version)
	}
	for _, bad := range []string{"1.2.3\r\nX: y", strings.Repeat("9", 65), "with space"} {
		r := httptest.NewRequest(http.MethodGet, "/outpost/hello", nil)
		r.Header[outpost.VersionHeader] = []string{bad}
		if got := outpostVersion(r); got != "" {
			t.Errorf("%q was taken for a version: %q", bad, got)
		}
	}
}

// A password checked at an outpost is recorded once, as the protocol it arrived on and
// naming the outpost. A RADIUS outpost's Access-Accept was recorded as an LDAP bind
// naming no outpost, and every wrong password twice, which the sign-in metrics read off
// the trail counted twice too; running the outpost's compose template found it.
func TestAnOutpostsBindIsAuditedOnceAndWhereItArrived(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	name := fmt.Sprintf("branch-%d", time.Now().UnixNano())
	_, token, err := store.CreateOutpost(ctx, f.pool, f.orgID, name, "radius", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.RemoveOutpost(context.Background(), f.pool, f.orgID, name) })
	core := httptest.NewServer(f.srv.Routes())
	t.Cleanup(core.Close)
	client, err := outpost.New(core.URL, token, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Authenticate(ctx, f.email, "not-the-password"); !errors.Is(err, outpost.ErrRefused) {
		t.Fatalf("a wrong password: %v", err)
	}
	if _, err := client.Authenticate(ctx, f.email, signInTestPassword); err != nil {
		t.Fatalf("the right password: %v", err)
	}

	rows, err := f.pool.Query(ctx, `
		SELECT event_type || ' ' || COALESCE(detail->>'via', '-') || ' ' || COALESCE(detail->>'outpost', '-')
		       || ' ' || COALESCE(detail->>'reason', '-')
		FROM core.audit_events
		WHERE (subject_id = $1::uuid OR detail->>'outpost' = $2) AND event_type LIKE 'login.%' ORDER BY id`,
		f.userID, name)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		got = append(got, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login.failed radius " + name + " bad_password",
		"login.succeeded radius " + name + " -",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the trail holds\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// A running outpost that has gone quiet is told from one that has not started and one
// taken out of service, and only the kinds that say hello can go quiet.
func TestOnlyARunningOutpostGoesStale(t *testing.T) {
	now := time.Now()
	long := now.Add(-2 * store.OutpostStaleAfter)
	recent := now.Add(-store.OutpostHeartbeat)
	for _, c := range []struct {
		name string
		o    store.Outpost
		want bool
	}{
		{"quiet", store.Outpost{Kind: "ldap", Enabled: true, LastSeenAt: &long}, true},
		{"quiet radius", store.Outpost{Kind: "radius", Enabled: true, LastSeenAt: &long}, true},
		{"heard from", store.Outpost{Kind: "ldap", Enabled: true, LastSeenAt: &recent}, false},
		{"never started", store.Outpost{Kind: "ldap", Enabled: true}, false},
		{"taken out of service", store.Outpost{Kind: "ldap", LastSeenAt: &long}, false},
		{"not a process", store.Outpost{Kind: "desktop", Enabled: true, LastSeenAt: &long}, false},
	} {
		if got := c.o.Stale(now); got != c.want {
			t.Errorf("%s: stale %v", c.name, got)
		}
	}
}
