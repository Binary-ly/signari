package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/prompts"
)

// TestPendingPromptsSeesAnUncommittedAnswer is a regression test for a bug that
// locked every user out.
//
// The answer to a prompt is written inside a transaction, and the same
// transaction then re-checks what is still outstanding. Reading through the
// POOL there cannot see the uncommitted write — so the prompt comes back, is
// answered again, comes back again, and nobody can ever sign in.
//
// It appears only once a deployment defines a prompt, which is exactly the kind
// of bug that reaches production: the code is correct until the feature is used.
func TestPendingPromptsSeesAnUncommittedAnswer(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "SET ROLE signari_maintenance"); err != nil {
		t.Fatalf("assuming signari_maintenance: %v", err)
	}

	var orgID, userID, promptID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ((SELECT id FROM core.instances ORDER BY created_at LIMIT 1),
		        'prompt-' || substr(md5(random()::text),1,8), 'Prompt Test')
		RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatalf("creating an organisation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM core.organizations WHERE id = $1::uuid`, orgID)
	})

	if err := pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4), 'hex'), 'prompt-test@example.invalid')
		RETURNING id::text`, orgID).Scan(&userID); err != nil {
		t.Fatalf("creating a user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.prompts (org_id, slug, title, fields, once)
		VALUES ($1::uuid, 'terms', 'Terms',
		        '[{"name":"accept","type":"checkbox","label":"Accept","required":true}]'::jsonb,
		        true)
		RETURNING id::text`, orgID).Scan(&promptID); err != nil {
		t.Fatalf("creating a prompt: %v", err)
	}

	// Outstanding to begin with.
	if got, err := PendingPrompts(ctx, pool, orgID, userID); err != nil || len(got) != 1 {
		t.Fatalf("expected one outstanding prompt, got %d (%v)", len(got), err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := RecordAnswer(ctx, tx, promptID, userID, orgID,
		prompts.Answers{"accept": "true"}); err != nil {
		t.Fatalf("recording the answer: %v", err)
	}

	// The heart of it: the SAME transaction must now see nothing outstanding.
	got, err := PendingPrompts(ctx, tx, orgID, userID)
	if err != nil {
		t.Fatalf("re-checking inside the transaction: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the prompt is still outstanding inside the transaction that "+
			"answered it (%d left). Sign-in would render it again, be answered "+
			"again, and loop forever", len(got))
	}

	// And the pool still sees it, because nothing is committed. This is what
	// makes the bug invisible from outside the transaction.
	if outside, err := PendingPrompts(ctx, pool, orgID, userID); err != nil ||
		len(outside) != 1 {
		t.Errorf("outside the transaction the prompt should still be outstanding, "+
			"got %d (%v)", len(outside), err)
	}
}
