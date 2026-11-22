package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// What comes after a credential is issued, and an offer kept to be fetched (12.08).

func (f *tokenFixture) issueOne(t *testing.T, token string) map[string]any {
	t.Helper()
	wa := newWallet(t)
	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := f.postJSON(t, "/oid4vci/credential", token, `{"credential_configuration_id":"IdentityCredential",
		"proofs":{"jwt":[`+mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusOK {
		t.Fatalf("issuance gave %d %v", status, resp)
	}
	return resp
}

func TestAWalletSaysWhatBecameOfACredential(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	token := f.mintAccessToken(t, "IdentityCredential")
	id, _ := f.issueOne(t, token)["notification_id"].(string)
	if id == "" {
		t.Fatal("no notification_id in the Credential Response")
	}
	notify := func(token, body string) (int, map[string]any) {
		t.Helper()
		return f.postJSON(t, "/oid4vci/notification", token, body)
	}
	said := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM core.audit_events
			WHERE event_type = 'oid4vci.credential_notified' AND subject_id = $1`, f.userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// §11.2: 204 is RECOMMENDED. §11: "it returns success" to the same call twice.
	for range 2 {
		if status, body := notify(token, `{"notification_id":"`+id+`","event":"credential_accepted"}`); status != http.StatusNoContent {
			t.Fatalf("a good notification gave %d %v", status, body)
		}
	}
	// A credential stored can later be deleted, and every word is kept.
	if status, body := notify(token, `{"notification_id":"`+id+`","event":"credential_deleted"}`); status != http.StatusNoContent {
		t.Errorf("a later word gave %d %v", status, body)
	}
	if got := said(); got != 3 {
		t.Errorf("%d words in the audit trail, want 3", got)
	}

	for name, c := range map[string]struct {
		body string
		code string
	}{
		"an id nobody was given": {`{"notification_id":"nothing","event":"credential_accepted"}`, "invalid_notification_id"},
		"no id":                  {`{"event":"credential_accepted"}`, "invalid_notification_request"},
		"an event of its own":    {`{"notification_id":"` + id + `","event":"credential_lost"}`, "invalid_notification_request"},
		"the wrong case":         {`{"notification_id":"` + id + `","event":"CREDENTIAL_ACCEPTED"}`, "invalid_notification_request"},
		"text outside the alphabet": {`{"notification_id":"` + id + `","event":"credential_failure",
			"event_description":"café"}`, "invalid_notification_request"},
		"not JSON": {`nope`, "invalid_notification_request"},
	} {
		if status, body := notify(token, c.body); status != http.StatusBadRequest || body["error"] != c.code {
			t.Errorf("%s gave %d %v", name, status, body)
		}
	}
	// §11: a valid Access Token, and only the one that asked: an id is no use to anybody else.
	if status, _ := notify("", `{"notification_id":"`+id+`","event":"credential_accepted"}`); status != http.StatusUnauthorized {
		t.Errorf("no token gave %d", status)
	}
	other := f.mintAccessToken(t, "IdentityCredential")
	if status, body := notify(other, `{"notification_id":"`+id+`","event":"credential_accepted"}`); status != http.StatusBadRequest ||
		body["error"] != "invalid_notification_id" {
		t.Errorf("another token gave %d %v", status, body)
	}
	if got := said(); got != 3 {
		t.Errorf("another token's word was kept: %d", got)
	}
}

func TestTheMetadataNamesTheNotificationEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil))
	var md map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatalf("%d: %v", rec.Code, err)
	}
	if md["notification_endpoint"] != f.srv.cfg.Issuer+"/oid4vci/notification" {
		t.Errorf("metadata says %v", md["notification_endpoint"])
	}
}

func TestAnOfferKeptByReferenceIsFetchedOnce(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = root
	offer := []byte(`{"credential_issuer":"https://id.example","grants":{"code":"the-pre-authorized-code"}}`)
	invocation, err := store.OfferByReference(ctx, f.pool, root, f.orgID, offer, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(invocation)
	if err != nil || u.Scheme != "openid-credential-offer" {
		t.Fatalf("invoked by %q (%v)", invocation, err)
	}
	address := u.Query().Get("credential_offer_uri")
	if !strings.Contains(address, store.CredentialOfferPath) || u.Query().Has("credential_offer") {
		t.Fatalf("the invocation is %q", invocation)
	}
	path := address[strings.Index(address, store.CredentialOfferPath):]
	fetch := func(srv *Server, path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	rec := fetch(f.srv, path)
	if rec.Code != http.StatusOK || rec.Body.String() != string(offer) {
		t.Fatalf("fetching gave %d %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("§4.1.3 wants application/json, and got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("an address that holds a code was served with %q", got)
	}

	var sealed []byte
	if err := f.pool.QueryRow(ctx, `SELECT offer_sealed FROM core.credential_offers WHERE org_id = $1::uuid
		ORDER BY created_at DESC LIMIT 1`, f.orgID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "the-pre-authorized-code") {
		t.Fatal("the code was kept in clear")
	}

	if rec := fetch(f.srv, store.CredentialOfferPath+"nothing"); rec.Code != http.StatusNotFound {
		t.Errorf("a handle nobody was given gave %d", rec.Code)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.credential_offers SET expires_at = now() - interval '1 second'
		WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	if rec := fetch(f.srv, path); rec.Code != http.StatusNotFound {
		t.Errorf("an expired offer gave %d", rec.Code)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if n, err := store.SweepExpiredCredentialOffers(ctx, tx, 1000); err != nil || n == 0 {
		t.Errorf("sweeping took %d: %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
