package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/store/storetest"
)

var bootstrapLink = regexp.MustCompile(`https://\S+/signup\?invite=\S+`)

// A first run, and the starts after it. Through run(), so the flags reach the command,
// and against what a compose file does: the same command on every start. What it must
// not do is the failure of each step run twice: a second organisation, a name somebody
// chose put back, a working link left lying about, or a link printed for ever.
func TestABootstrapStartsADeploymentAndIsSafeToRunAgain(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	if os.Getenv("SIGNARI_ROOT_KEY") == "" {
		t.Setenv("SIGNARI_ROOT_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })

	tail := make([]byte, 6)
	if _, err := rand.Read(tail); err != nil {
		t.Fatal(err)
	}
	issuer := "https://bootstrap-" + hex.EncodeToString(tail) + ".test"
	args := []string{"bootstrap", "-dsn", dsn, "-issuer", issuer, "-email", "First@Example.test", "-slug", "acme", "-name", "Acme"}
	start := func() string {
		t.Helper()
		out, err := captureStdout(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("bootstrap: %v\n%s", err, out)
		}
		return out
	}
	tokenOf := func(out string) string {
		t.Helper()
		link := bootstrapLink.FindString(out)
		if link == "" {
			t.Fatalf("no link in:\n%s", out)
		}
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(link, issuer+"/signup?") {
			t.Errorf("the link is not this deployment's: %s", link)
		}
		return u.Query().Get("invite")
	}

	first := tokenOf(start())

	var org, name, invited string
	var orgs, signing int
	if err := db.QueryRow(ctx, `
		SELECT o.id::text, i.id::text, (SELECT count(*) FROM core.organizations x WHERE x.instance_id = i.id),
		       (SELECT count(*) FROM core.signing_keys k WHERE k.instance_id = i.id)
		  FROM core.instances i JOIN core.organizations o ON o.instance_id = i.id
		 WHERE i.issuer = $1`, issuer).Scan(&org, &name, &orgs, &signing); err != nil {
		t.Fatalf("no instance and organisation: %v", err)
	}
	storetest.Forget(t, db, org)
	if orgs != 1 || signing < 2 {
		t.Errorf("%d organisations and %d signing keys, want one and both algorithms'", orgs, signing)
	}
	if err := db.QueryRow(ctx, `SELECT email FROM core.invitations WHERE token_hash = $1 AND org_id = $2::uuid
		AND used_at IS NULL AND revoked_at IS NULL`, store.HashToken(first), org).Scan(&invited); err != nil {
		t.Fatalf("the link printed is no live invitation: %v", err)
	}
	if invited != "first@example.test" {
		t.Errorf("the link is bound to %q", invited)
	}

	// Somebody names the deployment, and the next start must leave it.
	if _, err := db.Exec(ctx, `UPDATE core.instances SET display_name = 'Chosen' WHERE issuer = $1`, issuer); err != nil {
		t.Fatal(err)
	}
	second := tokenOf(start())
	if second == first {
		t.Fatal("the same link twice: it is stored hashed, so this one cannot be the first")
	}
	var chosen string
	if err := db.QueryRow(ctx, `SELECT display_name, (SELECT count(*) FROM core.organizations o WHERE o.instance_id = i.id)
		FROM core.instances i WHERE issuer = $1`, issuer).Scan(&chosen, &orgs); err != nil {
		t.Fatal(err)
	}
	if chosen != "Chosen" || orgs != 1 {
		t.Errorf("a second start left the name %q and %d organisations", chosen, orgs)
	}
	var live int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM core.invitations WHERE org_id = $1::uuid
		AND used_at IS NULL AND revoked_at IS NULL`, org).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("%d links work after a second start, want the new one alone", live)
	}

	// Once somebody is here, no link, on this start or any other.
	if _, err := db.Exec(ctx, `INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'first@example.test', sha256('h'::bytea) || sha256($1::text::bytea))`, org); err != nil {
		t.Fatal(err)
	}
	if out := start(); bootstrapLink.MatchString(out) {
		t.Errorf("a link was printed for a deployment with somebody in it:\n%s", out)
	}
}

// Refused before anything is written: half a deployment is worse than none.
func TestABootstrapAsksForWhatItNeeds(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-email", "a@b.test"}, "-issuer"},
		{[]string{"-issuer", "https://x.test"}, "-email"},
		{[]string{"-issuer", "https://x.test", "-email", "nobody"}, "not an address"},
		{[]string{"-issuer", "https://x.test", "-email", "a@b.test", "-slug", "Has Space"}, "not a slug"},
	} {
		err := run(append([]string{"bootstrap", "-dsn", dsn}, c.args...))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v gave %v, want it to say %q", c.args, err, c.want)
		}
	}
}
