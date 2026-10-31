package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/outpost"
	"signari.dev/engine/internal/store"
)

// An outpost through its whole life against a real core: registered, disabled, put back,
// rotated and removed. Each step is seen by the outpost's own client and by whoever binds
// through it, and none of them is a wrong password to the person behind it: a disabled
// outpost is told why, and a token the core has stopped taking is not "invalid credentials"
// to an office that typed its passwords correctly (8.31).
func TestAnOutpostThroughItsLife(t *testing.T) {
	f := newSignInFixture(t)
	ctx := context.Background()
	name := "life-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	_, token, err := store.CreateOutpost(ctx, f.pool, f.orgID, name, "ldap", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.RemoveOutpost(context.Background(), f.pool, f.orgID, name) })
	core := httptest.NewServer(f.srv.Routes())
	t.Cleanup(core.Close)

	hello := func(token string) (int, map[string]string, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, core.URL+"/outpost/hello", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out, resp.Header.Get("WWW-Authenticate")
	}
	check := func(token string) error {
		t.Helper()
		c, err := outpost.New(core.URL, token, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return c.Check(ctx)
	}
	if status, _, _ := hello(token); status != http.StatusOK {
		t.Fatalf("a new outpost's hello gave %d", status)
	}

	// A process started before each change, as one in a DMZ would have been.
	running, err := outpost.New(core.URL, token, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := ldapd.New(ldapd.Config{BaseDN: "dc=example,dc=test", UserAttr: "uid", MaxResults: 10,
		ReadTimeout: 5 * time.Second}, running, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lctx, cancel := context.WithCancel(ctx)
	go func() { _ = srv.Serve(lctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	bind := func() error {
		t.Helper()
		c, err := ldapclient.DialURL("ldap://" + ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		return c.Bind("uid=nobody-here,dc=example,dc=test", "a-password")
	}
	if err := bind(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials) {
		t.Fatalf("a wrong password through a working outpost gave %v", err)
	}

	if err := store.SetOutpostEnabled(ctx, f.pool, f.orgID, name, false); err != nil {
		t.Fatal(err)
	}
	if status, out, challenge := hello(token); status != http.StatusForbidden || out["error"] != "outpost_disabled" ||
		challenge != "" {
		t.Errorf("a disabled outpost got %d %v %q, want 403 outpost_disabled", status, out, challenge)
	}
	if err := check(token); err == nil || !strings.Contains(err.Error(), "outpost enable") {
		t.Errorf("starting a disabled outpost said %v; it should say how to put it back", err)
	}
	if err := bind(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
		t.Errorf("a bind through a disabled outpost gave %v, want unavailable", err)
	}

	if err := store.SetOutpostEnabled(ctx, f.pool, f.orgID, name, true); err != nil {
		t.Fatal(err)
	}
	if err := check(token); err != nil {
		t.Errorf("an outpost put back: %v", err)
	}

	rotated, err := store.RotateOutpostToken(ctx, f.pool, f.orgID, name)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == token {
		t.Fatal("a rotation gave the same token back")
	}
	if status, _, challenge := hello(token); status != http.StatusUnauthorized || !strings.Contains(challenge, "invalid_token") {
		t.Errorf("the old token after a rotation got %d %q", status, challenge)
	}
	if err := bind(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
		t.Errorf("a bind through an outpost with a stale token gave %v, want unavailable", err)
	}
	if err := check(rotated); err != nil {
		t.Errorf("the new token: %v", err)
	}

	if err := store.RemoveOutpost(ctx, f.pool, f.orgID, name); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := hello(rotated); status != http.StatusUnauthorized {
		t.Errorf("a removed outpost's token got %d", status)
	}
	if err := store.RemoveOutpost(ctx, f.pool, f.orgID, name); err != store.ErrOutpostUnknown {
		t.Errorf("removing it again: %v", err)
	}
	if _, err := store.RotateOutpostToken(ctx, f.pool, f.orgID, name); err != store.ErrOutpostUnknown {
		t.Errorf("rotating a removed outpost: %v", err)
	}
}
