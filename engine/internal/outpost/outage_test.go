package outpost

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/ldapd"
)

const outageBase = "dc=example,dc=test"

// An outpost whose core has gone is not a directory that has stopped believing
// anybody. Every way the core can fail to answer reaches an LDAP client as
// unavailable, and only the core's own refusal as a wrong password: a client told
// "invalid credentials" sends an office to reset passwords that are right, and a
// service told "no entry" takes a person for deleted.
func TestAnOutpostTellsAnOutageFromAWrongPassword(t *testing.T) {
	var status atomic.Int64
	body := func() string { return `{"username":"alice","active":true,"bind_proof":"proof"}` }
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := int(status.Load())
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(body()))
		}
	}))
	t.Cleanup(core.Close)

	client, err := New(core.URL, "token", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := ldapd.New(ldapd.Config{BaseDN: outageBase, UserAttr: "uid", MaxResults: 10, ReadTimeout: 5 * time.Second},
		client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	dial := func() *ldapclient.Conn {
		t.Helper()
		c, err := ldapclient.DialURL("ldap://" + ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	bind := func() error { return dial().Bind("uid=alice,"+outageBase, "a-password") }

	for _, c := range []struct {
		name   string
		status int
		code   uint16
	}{
		{"a wrong password", http.StatusUnauthorized, ldapclient.LDAPResultInvalidCredentials},
		{"a spent budget", http.StatusTooManyRequests, ldapclient.LDAPResultBusy},
		{"a broken core", http.StatusInternalServerError, ldapclient.LDAPResultUnavailable},
		{"a broken gateway", http.StatusBadGateway, ldapclient.LDAPResultUnavailable},
		{"a refused outpost", http.StatusForbidden, ldapclient.LDAPResultUnavailable},
	} {
		status.Store(int64(c.status))
		if err := bind(); !ldapclient.IsErrorWithCode(err, c.code) {
			t.Errorf("%s: a bind gave %v, want LDAP result %d", c.name, err, c.code)
		}
	}

	status.Store(http.StatusOK)
	real := body
	body = func() string { return `<html>` }
	if err := bind(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
		t.Errorf("an answer that does not parse: a bind gave %v", err)
	}
	body = real

	// Somebody bound, and then the core went: a search is not answered as empty.
	c := dial()
	if err := c.Bind("uid=alice,"+outageBase, "a-password"); err != nil {
		t.Fatalf("a bind with the core up: %v", err)
	}
	search := func() error {
		_, err := c.Search(ldapclient.NewSearchRequest("uid=alice,"+outageBase, ldapclient.ScopeBaseObject,
			ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"uid"}, nil))
		return err
	}
	if err := search(); err != nil {
		t.Fatalf("a search with the core up: %v", err)
	}
	status.Store(http.StatusBadGateway)
	if err := search(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
		t.Errorf("a search during an outage gave %v, want unavailable", err)
	}

	// Nothing there at all.
	core.Close()
	if err := bind(); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultUnavailable) {
		t.Errorf("a core that has gone: a bind gave %v", err)
	}
}
