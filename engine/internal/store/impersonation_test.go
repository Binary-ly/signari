package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Support access, against a real database.
//
// Every refusal here is the difference between a support feature and a back
// door, and each is a refusal rather than a log line on purpose.

// twoUsers gives an org, an administrator and someone to act as.
func twoUsers(t *testing.T, conn *pgx.Conn) (orgID, actorID, subjectID string) {
	t.Helper()
	ctx := context.Background()
	orgID, actorID, _, _ = fixture(t, conn)
	suffix := time.Now().UnixNano()
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, sha256($2::bytea) || sha256($3::bytea), $4) RETURNING id::text`,
		orgID, itoa(suffix+7), itoa(suffix+8), "sub"+itoa(suffix)+"@test").Scan(&subjectID))
	return orgID, actorID, subjectID
}

func TestImpersonationRefusesItsOwnFailureModes(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, actorID, subjectID := twoUsers(t, conn)

	begin := func(actor, subject, reason string) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = BeginImpersonation(ctx, tx, orgID, actor, subject, reason, "cid", time.Minute)
		return err
	}

	for _, c := range []struct {
		name, actor, subject, reason, want string
	}{
		{
			// Impersonating yourself launders an action into one that cannot be
			// attributed to the person who took it.
			"acting as yourself", actorID, actorID,
			"ticket 4471 -- investigating a login failure", "cannot impersonate themselves",
		},
		{
			// An organisation that cannot answer "why was this account accessed"
			// does not have support access, it has a back door.
			"no reason", actorID, subjectID, "", "a reason is required",
		},
		{
			"a reason that is not one", actorID, subjectID, "fix", "a reason is required",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := begin(c.actor, c.subject, c.reason)
			if err == nil {
				t.Fatal("accepted; this is the shape of a back door")
			}
			if !errors.Is(err, ErrImpersonationRefused) {
				t.Fatalf("err = %v, want ErrImpersonationRefused", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestImpersonationWillNotCrossAnOrganisation(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgA, actorID, _ := twoUsers(t, conn)
	_, otherUser, _ := twoUsers(t, conn) // a different org entirely

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// RLS does NOT catch this: the engine is exempt by design, and this code
	// runs as the engine. If the check is ever dropped, a support feature
	// becomes a tenant breach with a support feature's name on it.
	_, err = BeginImpersonation(ctx, tx, orgA, actorID, otherUser,
		"ticket 4471 -- investigating a login failure", "cid", time.Minute)
	if err == nil {
		t.Fatal("an administrator acted as a user in another organisation")
	}
	if !strings.Contains(err.Error(), "another organisation") {
		t.Fatalf("err = %q, want it to name the boundary", err)
	}
}

func TestImpersonationCannotChain(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, actorID, subjectID := twoUsers(t, conn)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const why = "ticket 4471 -- investigating a login failure"
	if _, err := BeginImpersonation(ctx, tx, orgID, actorID, subjectID, why, "cid",
		time.Minute); err != nil {
		t.Fatalf("the first episode: %v", err)
	}

	// The subject is now being impersonated. If THEY could start an episode, the
	// actor recorded on it would be a person who is not driving the browser, and
	// the chain back to a real administrator breaks at exactly the point an
	// investigation would want to follow it.
	_, err = BeginImpersonation(ctx, tx, orgID, subjectID, actorID, why, "cid", time.Minute)
	if err == nil {
		t.Fatal("an impersonated session started another impersonation")
	}
	if !strings.Contains(err.Error(), "cannot be chained") {
		t.Fatalf("err = %q, want it to name chaining", err)
	}
}

func TestImpersonationEndsByItself(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, actorID, subjectID := twoUsers(t, conn)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	im, err := BeginImpersonation(ctx, tx, orgID, actorID, subjectID,
		"ticket 4471 -- investigating a login failure", "cid", time.Minute)
	if err != nil {
		t.Fatalf("beginning: %v", err)
	}

	sid := "imp-" + itoa(time.Now().UnixNano())
	_, err = tx.Exec(ctx, `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, auth_time, not_after)
		VALUES ($1, sha256($2::bytea), $3, $4, now(), now() + interval '1 hour')`,
		sid, sid, orgID, subjectID)
	must(t, err)
	if err := AttachImpersonation(ctx, tx, im.ID, sid, actorID); err != nil {
		t.Fatalf("attaching: %v", err)
	}

	// The session must carry the actor, or minting a token has nothing to put in
	// `act` and support access is silent again.
	var impersonator string
	must(t, tx.QueryRow(ctx,
		`SELECT COALESCE(impersonator_id::text,'') FROM core.sessions WHERE sid = $1`,
		sid).Scan(&impersonator))
	if impersonator != actorID {
		t.Fatalf("session impersonator = %q, want %q", impersonator, actorID)
	}

	// Run it out and let the janitor find it.
	_, err = tx.Exec(ctx,
		`UPDATE core.impersonations SET expires_at = now() - interval '1 minute'
		  WHERE id = $1::uuid`, im.ID)
	must(t, err)

	n, err := ExpireImpersonations(ctx, tx)
	if err != nil {
		t.Fatalf("expiring: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d episodes, want 1", n)
	}

	var ended bool
	var revoked, reason *string
	must(t, tx.QueryRow(ctx, `
		SELECT i.ended_at IS NOT NULL, s.revoked_at::text, s.revocation_reason
		  FROM core.impersonations i JOIN core.sessions s ON s.sid = i.sid
		 WHERE i.id = $1::uuid`, im.ID).Scan(&ended, &revoked, &reason))
	if !ended {
		t.Fatal("the episode was not closed")
	}
	if revoked == nil {
		t.Fatal("the episode expired but its session is still live")
	}
	if reason == nil || *reason != string(ReasonImpersonationEnded) {
		t.Fatalf("revocation_reason = %v, want %q", reason, ReasonImpersonationEnded)
	}
}

func TestOnlyAGrantedGroupMayImpersonate(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	orgID, actorID, _ := twoUsers(t, conn)

	// Nobody has it by default. A feature like this arriving switched on for
	// whoever happens to be in a group called "admins" is a privilege escalation
	// delivered by an upgrade.
	may, err := MayImpersonate(ctx, conn, orgID, actorID)
	if err != nil {
		t.Fatalf("asking: %v", err)
	}
	if may {
		t.Fatal("the capability is granted by default")
	}

	var groupID string
	name := "support" + itoa(time.Now().UnixNano()%100000)
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.groups (org_id, name, display_name)
		VALUES ($1, $2, 'Support') RETURNING id::text`, orgID, name).Scan(&groupID))
	_, err = conn.Exec(ctx, `
		INSERT INTO core.group_members (group_id, user_id, org_id) VALUES ($1::uuid, $2::uuid, $3)`,
		groupID, actorID, orgID)
	must(t, err)

	// Membership alone is not the capability.
	may, err = MayImpersonate(ctx, conn, orgID, actorID)
	if err != nil {
		t.Fatalf("asking after joining: %v", err)
	}
	if may {
		t.Fatal("group membership alone granted the capability")
	}

	_, err = conn.Exec(ctx,
		`UPDATE core.groups SET may_impersonate = true WHERE id = $1::uuid`, groupID)
	must(t, err)

	may, err = MayImpersonate(ctx, conn, orgID, actorID)
	if err != nil {
		t.Fatalf("asking after the grant: %v", err)
	}
	if !may {
		t.Fatal("the grant had no effect")
	}
}
