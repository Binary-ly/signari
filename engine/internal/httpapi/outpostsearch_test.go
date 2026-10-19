package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"

	"signari.dev/engine/internal/ldapd"
	"signari.dev/engine/internal/outpost"
	"signari.dev/engine/internal/tokens"
)

// The core, not the outpost, decides who behind an LDAP outpost reads the
// directory. The token alone used to list every account in the organisation,
// because the search group was enforced by the outpost (migration 0142).

type outpostSearch struct {
	*signInFixture
	h         http.Handler
	token     string
	outpostID string
	bob       string // another account in the organisation
	group     string
}

func newOutpostSearch(t *testing.T) *outpostSearch {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	o := &outpostSearch{signInFixture: f, h: f.srv.Routes()}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	o.token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(o.token))
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.outposts (org_id, name, kind, token_hash)
		VALUES ($1::uuid, $2, 'ldap', $3) RETURNING id::text`,
		f.orgID, fmt.Sprintf("search-%d", time.Now().UnixNano()), sum[:]).Scan(&o.outpostID); err != nil {
		t.Fatalf("registering the outpost: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'b'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING email`, f.orgID).Scan(&o.bob); err != nil {
		t.Fatalf("a second account: %v", err)
	}
	o.group = fmt.Sprintf("readers-%d", time.Now().UnixNano())
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.groups (org_id, name, display_name) VALUES ($1::uuid, $2, $2)`,
		f.orgID, o.group); err != nil {
		t.Fatalf("a group: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.outposts WHERE org_id = $1::uuid`, f.orgID)
		_, _ = f.pool.Exec(c, `DELETE FROM core.groups WHERE org_id = $1::uuid AND name = $2`, f.orgID, o.group)
	})
	return o
}

func (o *outpostSearch) call(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+o.token)
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	o.h.ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (o *outpostSearch) bind(t *testing.T) string {
	t.Helper()
	code, out := o.call(t, "/outpost/authenticate", map[string]string{
		"username": o.email, "password": signInTestPassword,
	})
	proof, _ := out["bind_proof"].(string)
	if code != http.StatusOK || proof == "" {
		t.Fatalf("authenticate answered %d with no bind proof: %v", code, out)
	}
	return proof
}

func listed(out map[string]any) []string {
	var names []string
	users, _ := out["users"].([]any)
	for _, u := range users {
		m, _ := u.(map[string]any)
		name, _ := m["username"].(string)
		names = append(names, name)
	}
	return names
}

func (o *outpostSearch) setGroup(t *testing.T, group string, member bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := o.pool.Exec(ctx, `UPDATE core.outposts SET search_group = NULLIF($2, '')
		WHERE id = $1::uuid`, o.outpostID, group); err != nil {
		t.Fatal(err)
	}
	if member {
		if _, err := o.pool.Exec(ctx, `
			INSERT INTO core.group_members (group_id, user_id, org_id)
			SELECT g.id, $3::uuid, $1::uuid FROM core.groups g WHERE g.org_id = $1::uuid AND g.name = $2
			ON CONFLICT DO NOTHING`, o.orgID, o.group, o.userID); err != nil {
			t.Fatal(err)
		}
	} else {
		if _, err := o.pool.Exec(ctx, `
			DELETE FROM core.group_members WHERE user_id = $1::uuid
			   AND group_id IN (SELECT id FROM core.groups WHERE name = $2)`, o.userID, o.group); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnOutpostTokenReadsOnlyWhatThePersonWhoBoundMay(t *testing.T) {
	o := newOutpostSearch(t)

	// The token alone reads nothing.
	if code, _ := o.call(t, "/outpost/list", map[string]any{"limit": 500}); code != http.StatusUnauthorized {
		t.Errorf("a list with no bind proof answered %d, want 401", code)
	}
	if code, _ := o.call(t, "/outpost/lookup", map[string]any{"username": o.bob}); code != http.StatusUnauthorized {
		t.Errorf("a lookup with no bind proof answered %d, want 401", code)
	}

	// No search group: one entry, the person who bound.
	proof := o.bind(t)
	code, out := o.call(t, "/outpost/list", map[string]any{"limit": 500, "bind_proof": proof})
	if names := listed(out); code != http.StatusOK || len(names) != 1 || names[0] != o.email {
		t.Fatalf("with no search group the list was %d %q, want only %s", code, names, o.email)
	}
	if code, _ := o.call(t, "/outpost/lookup", map[string]any{"username": o.bob, "bind_proof": proof}); code != http.StatusNotFound {
		t.Errorf("another person's entry answered %d, want the 404 of an account that does not exist", code)
	}
	if code, _ := o.call(t, "/outpost/lookup", map[string]any{"username": o.email, "bind_proof": proof}); code != http.StatusOK {
		t.Errorf("the person's own entry answered %d", code)
	}

	// A member of the recorded group reads the directory, with the same proof:
	// the group is read on each request, not when the proof was issued.
	o.setGroup(t, o.group, true)
	_, out = o.call(t, "/outpost/list", map[string]any{"limit": 500, "bind_proof": proof})
	if names := listed(out); len(names) < 2 {
		t.Errorf("a member of the search group listed %q", names)
	}
	if code, _ := o.call(t, "/outpost/lookup", map[string]any{"username": o.bob, "bind_proof": proof}); code != http.StatusOK {
		t.Errorf("a member reading another entry answered %d", code)
	}
	// Removed from the group, back to one entry at once.
	o.setGroup(t, o.group, false)
	_, out = o.call(t, "/outpost/list", map[string]any{"limit": 500, "bind_proof": proof})
	if names := listed(out); len(names) != 1 {
		t.Errorf("after leaving the group the list was %q", names)
	}

	// A proof is good only from the outpost it was issued through, before it
	// expires, and for an account still active.
	o.setGroup(t, o.group, true)
	key, err := o.srv.anySigningKey()
	if err != nil {
		t.Fatal(err)
	}
	forge := func(cl outpostBindClaims) string {
		s, err := tokens.NewSigner(key).SignJSON(cl, typOutpostBind)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for name, p := range map[string]string{
		"another outpost's": forge(outpostBindClaims{Issuer: o.srv.cfg.Issuer, Outpost: "00000000-0000-0000-0000-000000000000",
			OrgID: o.orgID, Subject: o.email, Expiry: time.Now().Add(time.Hour).Unix()}),
		"an expired": forge(outpostBindClaims{Issuer: o.srv.cfg.Issuer, Outpost: o.outpostID,
			OrgID: o.orgID, Subject: o.email, Expiry: time.Now().Add(-time.Minute).Unix()}),
		"another issuer's": forge(outpostBindClaims{Issuer: "https://elsewhere.test", Outpost: o.outpostID,
			OrgID: o.orgID, Subject: o.email, Expiry: time.Now().Add(time.Hour).Unix()}),
		"a garbled": proof[:len(proof)-4] + "AAAA",
	} {
		if code, _ := o.call(t, "/outpost/list", map[string]any{"limit": 500, "bind_proof": p}); code != http.StatusUnauthorized {
			t.Errorf("%s proof answered %d, want 401", name, code)
		}
	}
	if _, err := o.pool.Exec(context.Background(),
		`UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, o.userID); err != nil {
		t.Fatal(err)
	}
	if code, _ := o.call(t, "/outpost/list", map[string]any{"limit": 500, "bind_proof": proof}); code != http.StatusUnauthorized {
		t.Errorf("a deactivated account's proof answered %d, want 401", code)
	}
}

// The journey as an LDAP client meets it: bind to an outpost, which asks a core
// it reaches over HTTP, and search. The outpost takes the search group from the
// core, so the two decide with one value.
func TestAnLDAPClientBehindAnOutpostSearchesAsTheCoreAllows(t *testing.T) {
	o := newOutpostSearch(t)
	core := httptest.NewServer(o.h)
	t.Cleanup(core.Close)

	search := func(t *testing.T) []string {
		t.Helper()
		client, err := outpost.New(core.URL, o.token, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
		srv := ldapd.New(ldapd.Config{
			BaseDN: "dc=example,dc=test", UserAttr: "uid", MaxResults: 500,
			ReadTimeout: 10 * time.Second, SearchGroup: client.SearchGroup(),
		}, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(func() { cancel(); _ = ln.Close() })
		go func() { _ = srv.Serve(ctx, ln) }()

		c, err := ldapclient.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.Bind("uid="+o.email+",dc=example,dc=test", signInTestPassword); err != nil {
			t.Fatalf("bind through the outpost: %v", err)
		}
		res, err := c.Search(ldapclient.NewSearchRequest("dc=example,dc=test",
			ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"uid"}, nil))
		if err != nil {
			t.Fatalf("search through the outpost: %v", err)
		}
		var uids []string
		for _, e := range res.Entries {
			uids = append(uids, e.GetAttributeValue("uid"))
		}
		return uids
	}

	if uids := search(t); len(uids) != 1 || uids[0] != o.email {
		t.Errorf("with no search group the outpost returned %q, want only %s", uids, o.email)
	}
	o.setGroup(t, o.group, true)
	uids := search(t)
	var sawBob bool
	for _, u := range uids {
		sawBob = sawBob || u == o.bob
	}
	if !sawBob {
		t.Errorf("a member of the registered search group did not see %s: %q", o.bob, uids)
	}
}
