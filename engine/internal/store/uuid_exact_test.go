package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// ExactUUID stands where `id::text = $1` stood, so it says yes to what that
// comparison could match and to nothing else: the form the database writes.
func TestAnExactUUIDIsTheFormTheDatabaseWrites(t *testing.T) {
	const id = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	if !ExactUUID(id) {
		t.Errorf("%s was refused", id)
	}
	for _, other := range []string{"", "not-a-uuid", strings.ToUpper(id), "{" + id + "}",
		strings.ReplaceAll(id, "-", ""), id + " "} {
		if ExactUUID(other) {
			t.Errorf("%q was taken for a uuid", other)
		}
		if ExactUUIDOrNil(other) != nil {
			t.Errorf("%q was bound", other)
		}
	}
	if got := ExactUUIDOrNil(id); got == nil || *got != id {
		t.Errorf("the id bound as %v", got)
	}
}

func TestSomebodyWhoCannotBeThereIsNoRows(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	orgID, userID, _, _ := fixture(t, conn)
	if got, err := OrgOfUser(ctx, conn, userID); err != nil || got != orgID {
		t.Errorf("a person's organisation read %q, %v", got, err)
	}
	for _, id := range []string{"not-a-uuid", strings.ToUpper(userID), "00000000-0000-0000-0000-000000000000"} {
		if _, err := OrgOfUser(ctx, conn, id); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("%q answered %v, want no rows", id, err)
		}
	}
}
