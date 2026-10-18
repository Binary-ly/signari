package httpapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"signari.dev/engine/internal/passwords"
)

// One user name in two organisations. User names are unique per organisation
// (users_org_username_key), so this is an ordinary state, and the RADIUS and
// LDAP paths looked the name up across every organisation: the VLAN query put a
// person on the other tenant's network, and the bind picked one of the two rows
// and refused the right person whenever it picked the other.

type twinFixture struct {
	f           *signInFixture
	otherOrg    string
	name        string
	ownVLAN     int
	otherVLAN   int
	otherPasswd string
}

func newTwinFixture(t *testing.T) *twinFixture {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()
	tf := &twinFixture{f: f, name: fmt.Sprintf("twin-%d", time.Now().UnixNano()),
		ownVLAN: 10, otherVLAN: 20, otherPasswd: "a-different-password-for-the-other-twin"}

	// An id that sorts before any random one, so a lookup that ignores the
	// organisation meets this twin first whether it reads the heap or the
	// (org_id, username) index. Otherwise the defect shows only when two random
	// ids happen to sort that way.
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (id, instance_id, slug, display_name)
		SELECT ('00000000-' || substr(gen_random_uuid()::text, 10))::uuid, instance_id,
		       'twin-' || substr(gen_random_uuid()::text, 1, 8), 'Twin'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&tf.otherOrg); err != nil {
		t.Fatal(err)
	}

	// Two fresh twins, the other organisation's created first and with the
	// lowest ids, so it comes first in the heap and in every index a plan might
	// read -- the old lookup's answer depended on which it met first.
	hasher := passwords.NewHasher(passwords.MemoryBudgetMiB)
	twin := func(org, idPrefix, password string) string {
		t.Helper()
		hash, err := hasher.Hash(ctx, password)
		if err != nil {
			t.Fatal(err)
		}
		var id string
		if err := f.pool.QueryRow(ctx, `
			INSERT INTO core.users (id, org_id, username, email, user_handle)
			VALUES (($3 || substr(gen_random_uuid()::text, 10))::uuid, $1::uuid, $2,
			        $2 || '@twin.test',
			        decode(md5($1::text||$2)||md5($2)||md5($1::text)||md5($2||$1::text), 'hex'))
			RETURNING id::text`, org, tf.name, idPrefix).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
			VALUES ($1::uuid, $2::uuid, $3, 'argon2id')`, id, org, hash); err != nil {
			t.Fatal(err)
		}
		return id
	}
	otherUser := twin(tf.otherOrg, "00000000-", tf.otherPasswd)
	ownUser := twin(f.orgID, "ffffffff-", signInTestPassword)

	// A VLAN rule in each organisation, the other one's at a higher priority so
	// a query that ignores the organisation reaches it first.
	for _, g := range []struct {
		org, user  string
		vlan, prio int
	}{{f.orgID, ownUser, tf.ownVLAN, 1}, {tf.otherOrg, otherUser, tf.otherVLAN, 100}} {
		if _, err := f.pool.Exec(ctx, `
			WITH g AS (
				INSERT INTO core.groups (org_id, name, display_name)
				VALUES ($1::uuid, 'net-' || substr(gen_random_uuid()::text, 1, 8), 'Net') RETURNING id
			), m AS (
				INSERT INTO core.group_members (group_id, user_id, org_id)
				SELECT id, $2::uuid, $1::uuid FROM g
			)
			INSERT INTO core.radius_group_authorization (org_id, group_id, vlan_id, priority)
			SELECT $1::uuid, id, $3, $4 FROM g`, g.org, g.user, g.vlan, g.prio); err != nil {
			t.Fatal(err)
		}
	}
	return tf
}

func (tf *twinFixture) radius(orgID string) *RADIUSAuthenticator {
	return NewRADIUSAuthenticator(tf.f.pool, passwords.NewHasher(passwords.MemoryBudgetMiB), orgID,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestARADIUSVLANComesFromTheListenersOrganisation(t *testing.T) {
	tf := newTwinFixture(t)
	ctx := context.Background()

	for org, want := range map[string]int{tf.f.orgID: tf.ownVLAN, tf.otherOrg: tf.otherVLAN} {
		got, err := tf.radius(org).Authorize(ctx, tf.name)
		if err != nil {
			t.Fatal(err)
		}
		if got.VLANID != want {
			t.Errorf("the listener for one organisation put %q on VLAN %d, want %d: "+
				"another tenant's network", tf.name, got.VLANID, want)
		}
	}
}

func TestABindFindsThePersonInTheListenersOrganisation(t *testing.T) {
	tf := newTwinFixture(t)
	ctx := context.Background()
	auth := NewLDAPAuthenticator(tf.f.pool, passwords.NewHasher(passwords.MemoryBudgetMiB), tf.f.orgID,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	for i := 0; i < 5; i++ {
		if id, err := auth.Authenticate(ctx, tf.name, signInTestPassword); err != nil || id == nil {
			t.Fatalf("attempt %d: the right person, the right password, refused (%v): the lookup "+
				"met the other organisation's %q first", i+1, err, tf.name)
		}
	}
	// And the other twin's password does not open this organisation's account.
	if _, err := auth.Authenticate(ctx, tf.name, tf.otherPasswd); err == nil {
		t.Fatal("the other organisation's password bound this organisation's account")
	}
}
