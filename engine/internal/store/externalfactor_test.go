package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const factorKeys = `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",` +
	`"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

func registerFactor(t *testing.T, q Execer, orgID string) {
	t.Helper()
	if _, err := SetExternalFactor(context.Background(), q, orgID, ExternalFactor{Name: "push",
		URL: "https://factor.example/ask", Issuer: "https://factor.example", JWKS: []byte(factorKeys),
		AMR: []string{"otp"}}); err != nil {
		t.Fatal(err)
	}
}

func TestANonceIsSpentOnceAndOnlyByWhoItWasFor(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	orgID, userID, _, _ := fixture(t, conn)
	otherOrg, otherUser, _, _ := fixture(t, conn)
	registerFactor(t, conn, orgID)
	registerFactor(t, conn, otherOrg)

	// A nonce is one row in one table, whoever it belongs to, so each run has its own.
	nonce, stale := "nonce-"+userID, "stale-"+userID
	if err := BeginFactorChallenge(ctx, conn, orgID, "push", userID, nonce, time.Minute); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ org, factor, user, nonce string }{
		"another person":       {orgID, "push", otherUser, nonce},
		"another organisation": {otherOrg, "push", userID, nonce},
		"another service":      {orgID, "other", userID, nonce},
		"another nonce":        {orgID, "push", userID, "other"},
	} {
		if spent, err := SpendFactorChallenge(ctx, conn, tc.org, tc.factor, tc.user, tc.nonce); err != nil || spent {
			t.Errorf("%s spent it (%v)", name, err)
		}
	}
	if spent, err := SpendFactorChallenge(ctx, conn, orgID, "push", userID, nonce); err != nil || !spent {
		t.Fatalf("its owner could not spend it (%v)", err)
	}
	if spent, err := SpendFactorChallenge(ctx, conn, orgID, "push", userID, nonce); err != nil || spent {
		t.Errorf("spent twice (%v)", err)
	}

	// Nothing kept but a digest.
	if err := BeginFactorChallenge(ctx, conn, orgID, "push", userID, stale, -time.Second); err != nil {
		t.Fatal(err)
	}
	var held int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM core.external_factor_challenges
		WHERE user_id = $1::uuid AND nonce_hash = $2`, userID, []byte(stale)).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Error("the nonce is stored as sent")
	}
	if spent, err := SpendFactorChallenge(ctx, conn, orgID, "push", userID, stale); err != nil || spent {
		t.Errorf("an expired nonce was spent (%v)", err)
	}
}

func TestAFlowCannotNameAServiceNobodyRegistered(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	orgID, _, _, _ := fixture(t, conn)
	doc := []byte(`version: 1
flows:
  - name: with-a-service
    on: authentication
    stages:
      - password
      - {stage: external_factor, factor: push}
      - session
    tests:
      - name: asked
        given: {}
        expect: [password, external_factor, session]
`)
	if _, err := ApplySignInFlow(ctx, conn, orgID, doc); !errors.Is(err, ErrInvalidDocument) ||
		!strings.Contains(err.Error(), `"push"`) {
		t.Fatalf("a flow naming nobody applied: %v", err)
	}
	registerFactor(t, conn, orgID)
	if _, err := ApplySignInFlow(ctx, conn, orgID, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveExternalFactor(ctx, conn, orgID, "push"); !errors.Is(err, ErrExternalFactorInUse) {
		t.Errorf("removed while the flow names it: %v", err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM core.sign_in_flows WHERE org_id = $1::uuid`, orgID); err != nil {
		t.Fatal(err)
	}
	if removed, err := RemoveExternalFactor(ctx, conn, orgID, "push"); err != nil || !removed {
		t.Errorf("removing it afterwards: %v, %v", removed, err)
	}
}
