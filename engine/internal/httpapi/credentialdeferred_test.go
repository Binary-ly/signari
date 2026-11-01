package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"signari.dev/engine/internal/sdjwt"
	"signari.dev/engine/internal/store"
)

// A credential somebody has to look at first (12.08, §9).

type deferredFixture struct {
	f     *tokenFixture
	token string
	wa    *wallet
}

func newDeferredFixture(t *testing.T) *deferredFixture {
	t.Helper()
	f := newTokenFixture(t)
	configureCredential(t, f)
	if _, err := f.pool.Exec(context.Background(), `UPDATE core.credential_configurations SET deferred = true
		WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	return &deferredFixture{f: f, token: f.mintAccessToken(t, "IdentityCredential"), wa: newWallet(t)}
}

// ask is a Credential Request, and the transaction it was answered with.
func (d *deferredFixture) ask(t *testing.T) string {
	t.Helper()
	_, nb := d.f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := d.f.postJSON(t, "/oid4vci/credential", d.token, `{"credential_configuration_id":"IdentityCredential",
		"proofs":{"jwt":[`+mustJSONString(t, d.wa.proof(t, d.f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusAccepted {
		t.Fatalf("a deferred configuration answered %d %v, want 202", status, resp)
	}
	if resp["credentials"] != nil {
		t.Fatalf("credentials were issued with nobody deciding: %v", resp)
	}
	transaction, _ := resp["transaction_id"].(string)
	if transaction == "" {
		t.Fatalf("no transaction_id in %v", resp)
	}
	if interval, _ := resp["interval"].(float64); interval <= 0 {
		t.Errorf("§8.3 wants a positive interval, and got %v", resp["interval"])
	}
	return transaction
}

func (d *deferredFixture) fetch(t *testing.T, token, transaction string) (int, map[string]any) {
	t.Helper()
	return d.f.postJSON(t, "/oid4vci/deferred_credential", token, `{"transaction_id":"`+transaction+`"}`)
}

func (d *deferredFixture) decide(t *testing.T, approve bool) {
	t.Helper()
	ctx := context.Background()
	waiting, err := store.PendingCredentialRequests(ctx, d.f.pool, d.f.orgID)
	if err != nil || len(waiting) != 1 {
		t.Fatalf("waiting: %v, %v", waiting, err)
	}
	if waiting[0].UserID != d.f.userID || waiting[0].Configuration != "IdentityCredential" {
		t.Errorf("waiting is %+v", waiting[0])
	}
	if err := store.DecideCredentialRequest(ctx, d.f.pool, d.f.orgID, waiting[0].ID, approve); err != nil {
		t.Fatal(err)
	}
}

func TestADeferredCredentialWaitsForADecision(t *testing.T) {
	d := newDeferredFixture(t)
	transaction := d.ask(t)

	status, resp := d.fetch(t, d.token, transaction)
	if status != http.StatusAccepted || resp["transaction_id"] != transaction {
		t.Fatalf("nobody having decided gave %d %v: §9.2 wants 202 and the same id", status, resp)
	}
	d.decide(t, true)

	status, resp = d.fetch(t, d.token, transaction)
	if status != http.StatusOK {
		t.Fatalf("an approved request gave %d %v", status, resp)
	}
	credentials, _ := resp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("issued %v", resp)
	}
	if resp["notification_id"] == nil || resp["notification_id"] == "" {
		t.Errorf("§9.2 allows a notification_id, as for any issuance: %v", resp)
	}
	first, _ := credentials[0].(map[string]any)
	signed, _, _, err := sdjwt.Split(first["credential"].(string))
	if err != nil {
		t.Fatal(err)
	}
	cnf, _ := claimsOfJWT(t, signed)["cnf"].(map[string]any)
	jwk, _ := cnf["jwk"].(map[string]any)
	proved, err := json.Marshal(d.wa.jwk.Public())
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(proved, &want); err != nil {
		t.Fatal(err)
	}
	if jwk == nil || jwk["x"] != want["x"] {
		t.Errorf("the credential is not bound to the key that was proved: %v", cnf)
	}

	// §9.1: invalid once the credential has been obtained.
	if status, resp := d.fetch(t, d.token, transaction); status != http.StatusBadRequest || resp["error"] != "invalid_transaction_id" {
		t.Errorf("fetching twice gave %d %v", status, resp)
	}
}

func TestADeniedRequestGetsNothing(t *testing.T) {
	d := newDeferredFixture(t)
	transaction := d.ask(t)
	d.decide(t, false)
	for range 2 {
		if status, resp := d.fetch(t, d.token, transaction); status != http.StatusBadRequest || resp["error"] != "credential_request_denied" {
			t.Fatalf("a denied request gave %d %v", status, resp)
		}
	}
	// A decision stands: a second click cannot make a no into a yes.
	var id string
	if err := d.f.pool.QueryRow(context.Background(), `SELECT id::text FROM core.credential_requests WHERE org_id = $1::uuid`,
		d.f.orgID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideCredentialRequest(context.Background(), d.f.pool, d.f.orgID, id, true); err != store.ErrCredentialRequestUnknown {
		t.Errorf("deciding again gave %v", err)
	}
}

func TestATransactionIsGoodForTheTokenThatAsked(t *testing.T) {
	d := newDeferredFixture(t)
	transaction := d.ask(t)
	d.decide(t, true)
	other := d.f.mintAccessToken(t, "IdentityCredential")
	if status, resp := d.fetch(t, other, transaction); status != http.StatusBadRequest || resp["error"] != "invalid_transaction_id" {
		t.Errorf("another token gave %d %v", status, resp)
	}
	if status, resp := d.fetch(t, d.token, "nothing"); status != http.StatusBadRequest || resp["error"] != "invalid_transaction_id" {
		t.Errorf("an id nobody was given gave %d %v", status, resp)
	}
	if status, _ := d.fetch(t, "", transaction); status != http.StatusUnauthorized {
		t.Errorf("no token gave %d", status)
	}
	if status, resp := d.f.postJSON(t, "/oid4vci/deferred_credential", d.token, `{}`); status != http.StatusBadRequest ||
		resp["error"] != "invalid_credential_request" {
		t.Errorf("no id gave %d %v", status, resp)
	}
}

func TestADeferredRequestIsReadAgainWhenItIsAnswered(t *testing.T) {
	d := newDeferredFixture(t)
	transaction := d.ask(t)
	d.decide(t, true)
	ctx := context.Background()
	if _, err := d.f.pool.Exec(ctx, `DELETE FROM core.credential_configurations WHERE org_id = $1::uuid`, d.f.orgID); err != nil {
		t.Fatal(err)
	}
	if status, resp := d.fetch(t, d.token, transaction); status != http.StatusBadRequest || resp["error"] != "credential_request_denied" {
		t.Errorf("a configuration removed since gave %d %v", status, resp)
	}
	if _, err := d.f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, d.f.userID); err != nil {
		t.Fatal(err)
	}
	if status, resp := d.fetch(t, d.token, transaction); status != http.StatusUnauthorized {
		t.Errorf("a person deactivated since gave %d %v", status, resp)
	}
}
