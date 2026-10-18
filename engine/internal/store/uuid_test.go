package store

import (
	"context"
	"testing"
)

// CanonicalUUID and PostgreSQL agree on every spelling, accepted or refused,
// because a guard and the write it guards disagreeing about which row an id
// names is how an administrator was taken over.
func TestCanonicalUUIDReadsIDsAsPostgreSQLDoes(t *testing.T) {
	pool := rateTestPool(t)
	ctx := context.Background()
	for _, in := range []string{
		"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
		"A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11",
		"{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}",
		"{a0eebc999c0b4ef8bb6d6bb9bd380a11}",
		"a0eebc999c0b4ef8bb6d6bb9bd380a11",
		"a0ee-bc99-9c0b-4ef8-bb6d-6bb9-bd38-0a11",
		"a0eebc9-99c0b-4ef8-bb6d-6bb9bd380a11",
		"a0ee--bc999c0b4ef8bb6d6bb9bd380a11",
		" a0eebc999c0b4ef8bb6d6bb9bd380a11",
		"{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
		"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11-",
		"-a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
		"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1",
		"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a111",
		"{}",
		"",
		"not-a-uuid",
		"g0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
	} {
		got, ok := CanonicalUUID(in)
		var want string
		err := pool.QueryRow(ctx, `SELECT $1::uuid::text`, in).Scan(&want)
		pgOK := err == nil
		if ok != pgOK || (ok && got != want) {
			t.Errorf("CanonicalUUID(%q) = (%q, %v); PostgreSQL gives (%q, accepted=%v)",
				in, got, ok, want, pgOK)
		}
	}
}
