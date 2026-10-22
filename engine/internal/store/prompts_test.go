package store

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/prompts"
)

// An edit to what a prompt says makes it pending again, and the earlier answer
// is kept with the version and the text it answered (5.13).
func TestAnEditedPromptIsAskedAgainAndTheOldAnswerIsKept(t *testing.T) {
	ctx := context.Background()
	conn := connect(t)
	tx, err := conn.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	var orgID, userID, promptID string
	must(t, tx.QueryRow(ctx, `SELECT id::text FROM core.organizations ORDER BY created_at LIMIT 1`).Scan(&orgID))
	must(t, tx.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1::uuid, decode(repeat(md5(random()::text),4), 'hex'), 'prompt-v-' || md5(random()::text) || '@example.invalid')
		RETURNING id::text`, orgID).Scan(&userID))
	must(t, tx.QueryRow(ctx, `INSERT INTO core.prompts (org_id, slug, title, body, fields, once)
		VALUES ($1::uuid, 'terms-' || md5(random()::text), 'Terms', 'The first terms.',
		        '[{"name":"accept","type":"checkbox","label":"Accept","required":true}]'::jsonb, true)
		RETURNING id::text`, orgID).Scan(&promptID))
	pending := func() []prompts.Prompt {
		t.Helper()
		ps, err := PendingPrompts(ctx, tx, orgID, userID)
		must(t, err)
		var mine []prompts.Prompt
		for _, p := range ps {
			if p.ID == promptID {
				mine = append(mine, p)
			}
		}
		return mine
	}
	if got := pending(); len(got) != 1 || got[0].Version != 1 {
		t.Fatalf("a new prompt: %+v, want pending at version 1", got)
	}
	must(t, RecordAnswer(ctx, tx, promptID, 1, userID, orgID, prompts.Answers{"accept": "true"}))
	if got := pending(); len(got) != 0 {
		t.Fatalf("answered, still pending: %+v", got)
	}

	// Moving it changes nothing anybody read.
	_, err = tx.Exec(ctx, `UPDATE core.prompts SET position = position + 1 WHERE id = $1::uuid`, promptID)
	must(t, err)
	if got := pending(); len(got) != 0 {
		t.Fatalf("reordering made the prompt pending again: %+v", got)
	}

	// New terms do.
	_, err = tx.Exec(ctx, `UPDATE core.prompts SET body = 'The second terms.' WHERE id = $1::uuid`, promptID)
	must(t, err)
	got := pending()
	if len(got) != 1 || got[0].Version != 2 {
		t.Fatalf("after new terms: %+v, want pending at version 2", got)
	}
	if err := RecordAnswer(ctx, tx, promptID, 1, userID, orgID, prompts.Answers{"accept": "true"}); err != ErrPromptChanged {
		t.Errorf("an answer to the replaced terms: %v, want ErrPromptChanged", err)
	}
	must(t, RecordAnswer(ctx, tx, promptID, 2, userID, orgID, prompts.Answers{"accept": "true"}))

	var answers, versions, hashes int
	must(t, tx.QueryRow(ctx, `SELECT count(*), count(DISTINCT prompt_version), count(DISTINCT content_hash)
		FROM core.prompt_responses WHERE prompt_id = $1::uuid AND user_id = $2::uuid`,
		promptID, userID).Scan(&answers, &versions, &hashes))
	if answers != 2 || versions != 2 || hashes != 2 {
		t.Errorf("kept %d answer(s) over %d version(s) and %d text(s); want both, each with its own", answers, versions, hashes)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT s`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE core.prompt_responses SET answers = '{}' WHERE prompt_id = $1::uuid`,
		promptID); err == nil {
		t.Error("an answer was changed in place; a response is a record")
	}
	_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT s`)
}

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

	if err := RecordAnswer(ctx, tx, promptID, 1, userID, orgID,
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
