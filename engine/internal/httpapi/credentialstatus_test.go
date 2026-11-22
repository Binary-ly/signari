package httpapi

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
)

// A credential taken back, the way a verifier learns of it: its place from the credential,
// the list from the URI there, the signature, then the bit.

type revocableFixture struct {
	f     *tokenFixture
	token string
	wa    *wallet
}

func newRevocableFixture(t *testing.T) *revocableFixture {
	t.Helper()
	f := newTokenFixture(t)
	configureCredential(t, f)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE core.credential_configurations SET revocable = true WHERE org_id = $1::uuid`, f.orgID); err != nil {
		t.Fatal(err)
	}
	var instanceID string
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`, f.orgID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(instanceID)
	return &revocableFixture{f: f, token: f.mintAccessToken(t, "IdentityCredential"), wa: newWallet(t)}
}

// place is what one issued credential says of itself.
type statusPlaceClaim struct {
	Index int    `json:"idx"`
	URI   string `json:"uri"`
}

func (r *revocableFixture) issue(t *testing.T) (string, statusPlaceClaim) {
	t.Helper()
	_, nb := r.f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := r.f.postJSON(t, "/oid4vci/credential", r.token, `{"credential_configuration_id":"IdentityCredential",
		"proofs":{"jwt":[`+mustJSONString(t, r.wa.proof(t, r.f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	credentials, _ := resp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("issued %v", resp)
	}
	credential, _ := credentials[0].(map[string]any)["credential"].(string)
	jws := strings.SplitN(credential, "~", 2)[0]
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Status struct {
			List statusPlaceClaim `json:"status_list"`
		} `json:"status"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Status.List.URI == "" {
		t.Fatalf("no place in %s", payload)
	}
	return credential, claims.Status.List
}

func (r *revocableFixture) get(t *testing.T, uri string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(uri, r.f.srv.cfg.Issuer), nil))
	return rec
}

// bit is §8.3 from a verifier's side, the checks a Status List Token owes before its
// answer means anything.
func (r *revocableFixture) bit(t *testing.T, place statusPlaceClaim) int {
	t.Helper()
	rec := r.get(t, place.URI)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/statuslist+jwt" {
		t.Fatalf("the list answered %d %q: %.200s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	object, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if typ := object.Signatures[0].Header.ExtraHeaders["typ"]; typ != "statuslist+jwt" {
		t.Errorf("typ is %v", typ)
	}
	key, err := r.f.srv.cfg.Keys.Active("ES256")
	if err != nil {
		t.Fatal(err)
	}
	jwk := key.PublicJWK()
	payload, err := object.Verify(jwk)
	if err != nil {
		t.Fatalf("the list's signature: %v", err)
	}
	var claims struct {
		Sub  string `json:"sub"`
		Exp  int64  `json:"exp"`
		List struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Sub != place.URI {
		t.Errorf("sub is %q and the credential's uri is %q: §8.3 has them equal", claims.Sub, place.URI)
	}
	if claims.Exp <= time.Now().Unix() {
		t.Errorf("the token came back expired: %d", claims.Exp)
	}
	compressed, err := base64.RawURLEncoding.DecodeString(claims.List.Lst)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	if place.Index/8 >= len(statuses) {
		t.Fatalf("index %d is out of a list of %d bytes", place.Index, len(statuses))
	}
	return int(statuses[place.Index/8]>>(place.Index%8)) & 1
}

func TestARevokedCredentialFlipsItsBit(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	_, place := r.issue(t)
	_, other := r.issue(t)
	if place.URI != other.URI {
		t.Errorf("one organisation has two lists at the same time: %s %s", place.URI, other.URI)
	}
	if r.bit(t, place) != 0 || r.bit(t, other) != 0 {
		t.Fatal("a credential just issued is not VALID")
	}
	got, err := store.IssuedCredentialsPage(ctx, r.f.pool, r.f.orgID, r.f.userID, "", 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v, %v", got, err)
	}
	var id string
	if err := r.f.pool.QueryRow(ctx, `SELECT id::text FROM core.issued_credentials
		WHERE org_id = $1::uuid AND idx = $2`, r.f.orgID, place.Index).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if n, err := store.RevokeCredential(ctx, r.f.pool, r.f.orgID, id); err != nil || n != 1 {
		t.Fatalf("%d, %v", n, err)
	}
	if r.bit(t, place) != 1 {
		t.Error("the revoked credential's bit is not set")
	}
	if r.bit(t, other) != 0 {
		t.Error("revoking one credential touched another's bit")
	}
	if n, err := store.RevokeCredential(ctx, r.f.pool, r.f.orgID, id); err != nil || n != 0 {
		t.Errorf("revoking it again: %d, %v", n, err)
	}
	if n, err := store.RevokeCredentialsOf(ctx, r.f.pool, r.f.orgID, r.f.userID); err != nil || n != 1 {
		t.Errorf("revoking the rest: %d, %v", n, err)
	}
	if r.bit(t, other) != 1 {
		t.Error("revoking what a person holds left a bit unset")
	}
}

// A credential of a configuration nobody asked to revoke says nothing, and leaves nothing
// behind: a record of who holds what is kept only where it is for something.
func TestACredentialNobodyCanRevokeKeepsNoRecord(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	if _, err := r.f.pool.Exec(ctx, `UPDATE core.credential_configurations SET revocable = false WHERE org_id = $1::uuid`, r.f.orgID); err != nil {
		t.Fatal(err)
	}
	_, nb := r.f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := r.f.postJSON(t, "/oid4vci/credential", r.token, `{"credential_configuration_id":"IdentityCredential",
		"proofs":{"jwt":[`+mustJSONString(t, r.wa.proof(t, r.f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusOK {
		t.Fatalf("it answered %d %v", status, resp)
	}
	var n int
	if err := r.f.pool.QueryRow(ctx, `SELECT count(*) FROM core.issued_credentials WHERE org_id = $1::uuid`, r.f.orgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d records kept", n)
	}
}

// Every way a person can be deleted ends at the foreign key, so the rule is the list's:
// a place with nobody behind it reads as revoked.
func TestACredentialOutlivesNobody(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	_, place := r.issue(t)
	if _, err := r.f.pool.Exec(ctx, `UPDATE core.issued_credentials SET user_id = NULL WHERE org_id = $1::uuid AND idx = $2`,
		r.f.orgID, place.Index); err != nil {
		t.Fatal(err)
	}
	if r.bit(t, place) != 1 {
		t.Error("a credential whose person is gone still reads VALID")
	}
}

// A batch of keys gets a place each (§13.2), at random (§12.5.1).
func TestEachCredentialHasAPlaceOfItsOwn(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	places := map[int]bool{}
	var last int
	sequential := 0
	for i := range 12 {
		_, place := r.issue(t)
		if places[place.Index] {
			t.Fatalf("index %d was handed out twice", place.Index)
		}
		places[place.Index] = true
		if i > 0 && (place.Index == last+1 || place.Index == last-1) {
			sequential++
		}
		last = place.Index
	}
	if sequential > 1 {
		t.Errorf("%d of twelve places were next to the last", sequential)
	}
	var allocated int
	if err := r.f.pool.QueryRow(ctx, `SELECT allocated FROM core.credential_status_lists WHERE org_id = $1::uuid`,
		r.f.orgID).Scan(&allocated); err != nil {
		t.Fatal(err)
	}
	if allocated != 12 {
		t.Errorf("allocated is %d", allocated)
	}
}

// A list that has taken its share stops, and the next credential starts another.
func TestAFullListStopsTakingCredentials(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	_, first := r.issue(t)
	if _, err := r.f.pool.Exec(ctx, `UPDATE core.credential_status_lists SET allocated = $2 WHERE org_id = $1::uuid`,
		r.f.orgID, oid4vci.StatusListFilledAt-1); err != nil {
		t.Fatal(err)
	}
	_, last := r.issue(t)
	if last.URI != first.URI {
		t.Error("the last place left went to a new list")
	}
	_, next := r.issue(t)
	if next.URI == first.URI {
		t.Error("a full list took another credential")
	}
	if r.bit(t, first) != 0 {
		t.Error("a full list stopped answering")
	}
}

func TestAStatusListOfNobodyIsNotFound(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	for _, path := range []string{"/oid4vci/status/not-a-uuid", "/oid4vci/status/00000000-0000-4000-8000-000000000000"} {
		if rec := r.get(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, rec.Code)
		}
	}
	// Another instance's list is another issuer's.
	_, place := r.issue(t)
	var other string
	if err := r.f.pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://elsewhere-' || gen_random_uuid() || '.test', 'Elsewhere') RETURNING id::text`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.f.pool.Exec(context.Background(), `DELETE FROM core.instances WHERE id = $1::uuid`, other)
	})
	r.f.srv.SetInstance(other)
	if rec := r.get(t, place.URI); rec.Code != http.StatusNotFound {
		t.Errorf("another instance's list answered %d", rec.Code)
	}
}

// §8.4: "If the Server does not support the additional query parameter, it SHOULD return
// a status code of 501 (Not Implemented)", and §8.1 wants it readable from a browser.
func TestAStatusListSaysWhatItDoesNotKeep(t *testing.T) {
	r := newRevocableFixture(t)
	_, place := r.issue(t)
	if rec := r.get(t, fmt.Sprintf("%s?time=%d", place.URI, time.Now().Unix())); rec.Code != http.StatusNotImplemented {
		t.Errorf("a question about the past answered %d", rec.Code)
	}
	rec := r.get(t, place.URI)
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("the list cannot be read from a browser")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=300") {
		t.Errorf("Cache-Control is %q", cc)
	}
}

// A retired list and its rows go together, so no place comes free to be handed out twice,
// and one with anything still good stays.
func TestOnlyAFinishedListIsRetired(t *testing.T) {
	r := newRevocableFixture(t)
	ctx := context.Background()
	_, place := r.issue(t)
	listID := place.URI[strings.LastIndex(place.URI, "/")+1:]
	sweep := func() {
		t.Helper()
		tx, err := r.f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.SweepCredentialStatusLists(ctx, tx, time.Hour, 100); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	exists := func() bool {
		t.Helper()
		var found bool
		if err := r.f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.credential_status_lists WHERE id = $1::uuid)`,
			listID).Scan(&found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	expire := func() {
		t.Helper()
		if _, err := r.f.pool.Exec(ctx, `UPDATE core.issued_credentials SET expires_at = now() - interval '2 hours'
			WHERE list_id = $1::uuid`, listID); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	sweep()
	if !exists() {
		t.Error("a list still filling was retired")
	}
	if _, err := r.f.pool.Exec(ctx, `UPDATE core.credential_status_lists SET full_up = true WHERE id = $1::uuid`, listID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.pool.Exec(ctx, `UPDATE core.issued_credentials SET expires_at = NULL WHERE list_id = $1::uuid`, listID); err != nil {
		t.Fatal(err)
	}
	sweep()
	if !exists() {
		t.Error("a list with a credential that does not expire was retired")
	}
	expire()
	sweep()
	if exists() {
		t.Error("a full list of expired credentials stayed")
	}
}
