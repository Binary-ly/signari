package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/txntoken"
)

// mintAccessTokenWithScope produces a subject token that actually carries scope,
// which the txn-token path needs: the scope ceiling is read from the verified
// token, so a token with none can never yield a Txn-Token with any.
func (f *tokenFixture) mintAccessTokenWithScope(t *testing.T, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := f.srv.mintSet(ctx, tx, c, f.orgID, f.userID, "", "", scopes, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

func (f *tokenFixture) txnToken(t *testing.T, subject, subjectType, scope string) (int, map[string]any) {
	t.Helper()
	return f.post(t, url.Values{
		"grant_type":           {oauth.GrantTypeTokenExchange},
		"requested_token_type": {txntoken.TokenType},
		"subject_token":        {subject},
		"subject_token_type":   {subjectType},
		"audience":             {exchangeAudience},
		"scope":                {scope},
		"client_id":            {f.clientID},
	})
}

// draft-ietf-oauth-transaction-tokens-11 §13.15: a replacement "MUST NOT enable
// modification to asserted values that expand the scope of permitted actions".
//
// internal/txntoken proves Replace refuses to widen. What was untested is
// whether the endpoint SAYS so correctly, and that turned out to matter: the
// handler chose its OAuth error code with
// `strings.Contains(err.Error(), "widen")`, so the mapping held only for as long
// as nobody reworded the sentence in a different package. A scope violation
// reported as `invalid_grant` tells the caller its token is bad, and it would
// have gone looking at the token rather than at what it asked for.
func TestAReplacementCannotWidenScopeThroughTheEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)

	subject := f.mintAccessTokenWithScope(t, []string{"read", "write"})

	// Hop one: a Txn-Token carrying only `read`, well inside the ceiling.
	status, body := f.txnToken(t, subject, "urn:ietf:params:oauth:token-type:access_token", "read")
	if status != http.StatusOK {
		t.Fatalf("the initial txn-token request gave %d: %v", status, body)
	}
	first, _ := body["access_token"].(string)
	if first == "" {
		t.Fatalf("no txn-token in %v", body)
	}
	if body["token_type"] != "N_A" {
		t.Errorf("token_type = %v, want N_A (§11.4)", body["token_type"])
	}
	if body["issued_token_type"] != txntoken.TokenType {
		t.Errorf("issued_token_type = %v (§11.4)", body["issued_token_type"])
	}
	// §11.4: "The Txn-Token Response MUST NOT include the refresh_token value."
	if _, has := body["refresh_token"]; has {
		t.Error("the response carries a refresh_token, which §11.4 forbids: it " +
			"would turn a five-minute internal assertion into a standing credential")
	}

	// Hop two asks for `write`, which the presented Txn-Token does not carry --
	// even though the ORIGINAL access token did. The ceiling is the token in
	// hand, not the one it descended from.
	status, body = f.txnToken(t, first, txntoken.TokenType, "write")
	if status == http.StatusOK {
		t.Fatalf("a replacement widened its scope from `read` to `write`; the "+
			"authority a workload holds grew as the request travelled inward, "+
			"which is the attack this format exists to stop: %v", body)
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error = %v, want invalid_scope: a widening attempt reported as "+
			"anything else sends the caller to debug the wrong thing (%v)",
			body["error"], body)
	}
}

// The narrowing direction must still work, or the guard above would be a guard
// against replacement itself.
func TestAReplacementMayNarrowScope(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)

	subject := f.mintAccessTokenWithScope(t, []string{"read", "write"})
	status, body := f.txnToken(t, subject, "urn:ietf:params:oauth:token-type:access_token", "read write")
	if status != http.StatusOK {
		t.Fatalf("the initial txn-token request gave %d: %v", status, body)
	}
	first, _ := body["access_token"].(string)

	status, body = f.txnToken(t, first, txntoken.TokenType, "read")
	if status != http.StatusOK {
		t.Fatalf("a replacement narrowing `read write` to `read` was refused "+
			"with %d: §13.15 explicitly permits reducing scope (%v)", status, body)
	}
}
