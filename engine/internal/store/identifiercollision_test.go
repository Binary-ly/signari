package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// One person's username may not be another's email in the same organisation
// (2.59, migration 0158). Sign-in matches either field and refuses two people,
// so the collision refused both; each field was unique only on its own. Refused
// as a unique violation, so every writer's existing conflict handling answers
// it; another organisation, or a person's own pair, is untouched.
func TestAUsernameCannotBeAnotherPersonsEmail(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	stamp := fmt.Sprint(time.Now().UnixNano())
	var org, other string
	for _, id := range []*string{&org, &other} {
		must(t, conn.QueryRow(ctx, `
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT instance_id, 'idc-' || substr(gen_random_uuid()::text, 1, 8), 'collision'
			  FROM core.organizations ORDER BY created_at LIMIT 1 RETURNING id::text`).Scan(id))
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = conn.Exec(c, `DELETE FROM core.users WHERE org_id IN ($1::uuid, $2::uuid)`, org, other)
		_, _ = conn.Exec(c, `DELETE FROM core.organizations WHERE id IN ($1::uuid, $2::uuid)`, org, other)
	})
	add := func(orgID, email, username string) error {
		_, err := conn.Exec(ctx, `
			INSERT INTO core.users (org_id, email, username, user_handle)
			VALUES ($1::uuid, NULLIF($2, ''), NULLIF($3, ''), decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
			        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))`, orgID, email, username)
		return err
	}
	taken := "taken-" + stamp + "@example.test"
	must(t, add(org, taken, ""))

	if err := add(org, "", "TAKEN-"+stamp+"@example.test"); !isUniqueViolation(err) {
		t.Errorf("a username equal to another person's address was accepted (err = %v)", err)
	}
	must(t, add(org, "", "handle-"+stamp))
	if err := add(org, "handle-"+stamp, ""); !isUniqueViolation(err) {
		t.Errorf("an address equal to another person's username was accepted (err = %v)", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE core.users SET username = $2 WHERE org_id = $1::uuid AND username = $3`,
		org, taken, "handle-"+stamp); !isUniqueViolation(err) {
		t.Errorf("renaming a username to another person's address was accepted (err = %v)", err)
	}
	if err := add(other, "", taken); err != nil {
		t.Errorf("another organisation's username was refused: %v", err)
	}
	same := "same-" + stamp + "@example.test"
	if err := add(org, same, same); err != nil {
		t.Errorf("a person whose username is their own address was refused: %v", err)
	}
}
