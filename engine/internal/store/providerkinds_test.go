package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/federation"
)

// The database must accept every provider kind the code can produce.
//
// The set of federated providers is written down twice: as a presets map in
// internal/federation, and as a CHECK constraint on core.identity_providers.
// Two lists that must agree and cannot see each other is how a new provider
// comes to work everywhere except the one place it is stored — which is what
// happened when Apple, GitLab, Discord, Twitch and LinkedIn were added. The
// preset was right, the CLI help was right, and registering one failed with a
// constraint violation naming nothing useful.
//
// Rather than remember, this asks the database.
func TestEveryProviderKindIsStorable(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var def string
	if err := conn.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conname = 'identity_providers_kind_check'`).Scan(&def); err != nil {
		t.Fatalf("reading the kind constraint: %v", err)
	}

	kinds := federation.Kinds()
	if len(kinds) < 5 {
		t.Fatalf("only %d kinds were found; this test is reading the federation "+
			"package wrong", len(kinds))
	}

	var missing []string
	for _, k := range kinds {
		// The constraint spells each value as 'name'::text.
		if !strings.Contains(def, "'"+string(k)+"'") {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		t.Errorf("these provider kinds exist in code but the database will refuse "+
			"them:\n  %s\n\nconstraint: %s\n\nAdd them in a migration, or the "+
			"provider works everywhere except the moment somebody registers one.",
			strings.Join(missing, ", "), def)
	}

	// And the other direction: a value the constraint permits that no preset
	// backs would be a kind an operator can store and the engine cannot use.
	// `saml` is deliberately excluded — it is a real kind with no preset,
	// because a SAML upstream's endpoints come from its metadata.
	known := map[string]bool{"saml": true}
	for _, k := range kinds {
		known[string(k)] = true
	}
	for _, quoted := range strings.Split(def, "'") {
		if quoted == "" || strings.ContainsAny(quoted, " ,()[]:=") {
			continue
		}
		if !known[quoted] {
			t.Errorf("the database permits kind %q, which no preset backs: an "+
				"operator can store it and the engine cannot use it", quoted)
		}
	}
}
