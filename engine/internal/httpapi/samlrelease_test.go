package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// What a provider is registered to receive, through the endpoint. Whether it has
// any of this to ask for comes with the provider, so this is what says the asking
// still happens: the stores are tested on their own, and a wrong answer here is an
// assertion that signs and verifies with nothing in it.
func TestAnAssertionCarriesWhatItsProviderReleases(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	rf.f.srv.root = root
	id := rf.providerID(t, rf.own)
	stamp := time.Now().UnixNano()

	group := fmt.Sprintf("release-%d", stamp)
	if _, err := rf.f.pool.Exec(ctx, `
		WITH g AS (
			INSERT INTO core.groups (org_id, name, display_name)
			VALUES ($1::uuid, $3, 'Engineers') RETURNING id
		), m AS (
			INSERT INTO core.group_members (group_id, user_id, org_id)
			SELECT id, $2::uuid, $1::uuid FROM g
		)
		INSERT INTO core.saml_group_release (provider_id, org_id, attribute_name)
		VALUES ($4::uuid, $1::uuid, 'memberOf')`, rf.f.orgID, rf.f.userID, group, id); err != nil {
		t.Fatal(err)
	}

	attribute := fmt.Sprintf("dept_%d", stamp)
	tx, err := rf.f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.DeclareAttribute(ctx, tx, rf.f.orgID, store.Attribute{Name: attribute, ValueType: "string"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserAttribute(ctx, tx, rf.f.userID, rf.f.orgID, attribute, "Engineering", root); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE core.saml_providers SET attributes = jsonb_build_object('department', $2::text)
		WHERE id = $1::uuid`, id, attribute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	_, doc := rf.samlSSO(t, rf.own)
	for _, want := range []string{`Name="memberOf"`, group, `Name="department"`, "Engineering"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the assertion has no %q: %.900s", want, doc)
		}
	}
}

// ForceAuthn is met by a sign-in after the request and by nothing before it, and
// the assertion says when that sign-in was, not when it was written.
func TestForceAuthnIsMetByASignInAfterTheRequest(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	signedInAgo := func(ago string) {
		t.Helper()
		if _, err := rf.f.pool.Exec(ctx, `UPDATE core.sessions SET auth_time = now() - $2::interval
			WHERE user_id = $1::uuid`, rf.f.userID, ago); err != nil {
			t.Fatal(err)
		}
	}
	forced := func(issued time.Time) *httptest.ResponseRecorder {
		t.Helper()
		req := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%d" Version="2.0" ForceAuthn="true"
 IssueInstant="%s" Destination="https://signin-test.example/saml/sso"
 AssertionConsumerServiceURL="https://sp.test/acs"
 ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
			time.Now().UnixNano(), issued.UTC().Format(time.RFC3339), rf.own)
		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))}}
		r := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
		rec := httptest.NewRecorder()
		rf.f.srv.Routes().ServeHTTP(rec, r)
		return rec
	}

	signedInAgo("1 hour")
	if rec := forced(time.Now()); rec.Code != http.StatusSeeOther || issued(t, rec) != "" {
		t.Errorf("a session from before the request answered %d: %.200s", rec.Code, rec.Body.String())
	}

	signedInAgo("30 seconds")
	doc := issued(t, forced(time.Now().Add(-time.Minute)))
	m := regexp.MustCompile(`AuthnInstant="([^"]+)"`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("a sign-in after the request got no assertion: %.300s", doc)
	}
	at, err := time.Parse(time.RFC3339, m[1])
	if err != nil {
		t.Fatal(err)
	}
	if off := time.Since(at); off < 20*time.Second || off > time.Minute {
		t.Errorf("AuthnInstant is %s, %s ago, for a sign-in thirty seconds ago", m[1], off)
	}
}

func TestAProviderOfAnotherInstanceIsNoProviderHere(t *testing.T) {
	rf := newRealmFixture(t)
	if err := rf.f.pool.QueryRow(context.Background(), `
		INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://other-' || gen_random_uuid() || '.test', 'Other') RETURNING id::text`).
		Scan(&rf.f.srv.instanceID); err != nil {
		t.Fatal(err)
	}
	if code, doc := rf.samlSSO(t, rf.own); code != http.StatusBadRequest || doc != "" {
		t.Errorf("it answered %d: %.200s", code, doc)
	}
}
