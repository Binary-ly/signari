package store

import (
	"context"
	"errors"
	"testing"
)

// A policy or flow document that will not load is refused before anything is
// written, on a connection with no transaction around it too: the commands
// write that way, and a document stored first and refused after would sit in
// the table the engine reads, refused at load, while the operator believes it
// is deployed.
func TestADocumentThatWillNotLoadIsNeverStored(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	var orgID string
	must(t, conn.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ((SELECT id FROM core.instances ORDER BY created_at LIMIT 1),
		        'docs-' || substr(md5(random()::text),1,8), 'Documents')
		RETURNING id::text`).Scan(&orgID))
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, orgID)
	})

	// Its own test disagrees with it.
	policy := "version: 1\ndefault: deny\npolicies: []\ntests:\n  - name: open\n" +
		"    given: {client: anything}\n    expect: allow\n"
	if _, err := ApplyAccessPolicy(ctx, conn, orgID, []byte(policy)); !errors.Is(err, ErrInvalidDocument) {
		t.Errorf("a policy whose test fails answered %v", err)
	}
	if _, err := ApplySignInFlow(ctx, conn, orgID, []byte("flows: [")); !errors.Is(err, ErrInvalidDocument) {
		t.Errorf("an unparseable flow answered %v", err)
	}
	for _, read := range []func() (AppliedDocument, error){
		func() (AppliedDocument, error) { return AccessPolicyOf(ctx, conn, orgID) },
		func() (AppliedDocument, error) { return SignInFlowOf(ctx, conn, orgID) },
	} {
		got, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if got.AppliedAt != nil {
			t.Errorf("a refused document was stored: %q", got.Document)
		}
	}
}
