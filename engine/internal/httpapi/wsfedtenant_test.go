package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// WS-Federation reached the assertion with neither of the checks the SAML
// endpoint makes: whose application the realm is, and whether its operator had
// switched it off. A session in one organisation could be turned into a signed
// token for another organisation's realm.

type realmFixture struct {
	f      *signInFixture
	cookie string
	// own and foreign are entity IDs of enabled realms in the user's
	// organisation and in another one; disabled is the user's, switched off.
	own, foreign, disabled string
}

func newRealmFixture(t *testing.T) *realmFixture {
	t.Helper()
	f := newSignInFixture(t)
	ctx := context.Background()

	// SAML signs with RS256; the fixture's key set has only ES256.
	es, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	esA, _ := keys.WithState(es, keys.StateActive)
	rsA, _ := keys.WithState(rs, keys.StateActive)
	set, err := keys.NewSet(esA, rsA)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Keys = set
	// The SAML certificate is stored on the key's row, so the RS256 key needs
	// one. Passive, in the fixture's own instance: nothing else signs with it.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		SELECT $1, instance_id, 'RS256', 'passive', '{}', 'test:in-memory'
		  FROM core.organizations WHERE id = $2::uuid`, rs.KID(), f.orgID); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprint(time.Now().UnixNano())
	rf := &realmFixture{f: f,
		own: "urn:test:own:" + suffix, foreign: "urn:test:foreign:" + suffix,
		disabled: "urn:test:disabled:" + suffix}

	var otherOrg string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.organizations (instance_id, slug, display_name)
		SELECT instance_id, 'other-' || substr(gen_random_uuid()::text, 1, 8), 'Other'
		  FROM core.organizations WHERE id = $1::uuid RETURNING id::text`, f.orgID).Scan(&otherOrg); err != nil {
		t.Fatal(err)
	}
	for _, sp := range []struct {
		org, entity string
		enabled     bool
	}{{f.orgID, rf.own, true}, {otherOrg, rf.foreign, true}, {f.orgID, rf.disabled, false}} {
		if _, err := f.pool.Exec(ctx, `
			WITH p AS (
				INSERT INTO core.saml_providers (org_id, entity_id, display_name, enabled)
				VALUES ($1::uuid, $2, 'SP', $3) RETURNING id
			)
			INSERT INTO core.saml_acs_urls (provider_id, url, is_default)
			SELECT id, 'https://sp.test/acs', true FROM p`, sp.org, sp.entity, sp.enabled); err != nil {
			t.Fatal(err)
		}
	}
	rf.cookie = f.signInAndReturnCookie(t)
	return rf
}

func (rf *realmFixture) signIn(realm string, withSession bool) *httptest.ResponseRecorder {
	q := url.Values{"wa": {"wsignin1.0"}, "wtrealm": {realm}}
	r := httptest.NewRequest(http.MethodGet, "/wsfed?"+q.Encode(), nil)
	if withSession {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: rf.cookie})
	}
	rec := httptest.NewRecorder()
	rf.f.srv.Routes().ServeHTTP(rec, r)
	return rec
}

func (rf *realmFixture) tokensIssued(t *testing.T) int {
	t.Helper()
	var n int
	if err := rf.f.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM core.audit_events
		 WHERE subject_id = $1::uuid AND event_type = 'wsfed.token_issued'`, rf.f.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWSFedRefusesAnotherOrganisationsRealm(t *testing.T) {
	rf := newRealmFixture(t)

	rec := rf.signIn(rf.foreign, true)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "RequestSecurityTokenResponse") {
		t.Fatalf("a session in one organisation asked for another's realm and got %d", rec.Code)
	}
	if n := rf.tokensIssued(t); n != 0 {
		t.Fatalf("%d WS-Federation token(s) issued for another organisation's realm", n)
	}

	// The control: the user's own realm still works, so the refusal above is the
	// check and not a broken fixture.
	rec = rf.signIn(rf.own, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "wresult") {
		t.Fatalf("the user's own realm answered %d, want the token form", rec.Code)
	}
	if n := rf.tokensIssued(t); n != 1 {
		t.Fatalf("%d tokens issued for the user's own realm, want 1", n)
	}
}

func TestWSFedRefusesADisabledRealm(t *testing.T) {
	rf := newRealmFixture(t)
	if rec := rf.signIn(rf.disabled, true); rec.Code != http.StatusForbidden {
		t.Fatalf("a disabled realm answered %d to a signed-in user, want 403", rec.Code)
	}
	// Before the sign-in, too: nobody should be sent to authenticate for an
	// application that will be refused anyway.
	if rec := rf.signIn(rf.disabled, false); rec.Code != http.StatusForbidden {
		t.Fatalf("a disabled realm answered %d to a signed-out browser, want 403 rather "+
			"than a sign-in page", rec.Code)
	}
	if n := rf.tokensIssued(t); n != 0 {
		t.Fatalf("%d tokens issued for a disabled realm", n)
	}
}

// issueSAMLAssertion is the one function that signs an assertion for SAML and
// WS-Federation. It refuses on its own, so a caller that forgets is refused too.
func TestNoAssertionIsSignedForAnUnusableServiceProvider(t *testing.T) {
	rf := newRealmFixture(t)
	ctx := context.Background()
	var sid string
	if err := rf.f.pool.QueryRow(ctx, `
		SELECT sid FROM core.sessions WHERE user_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		rf.f.userID).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	for _, entity := range []string{rf.foreign, rf.disabled} {
		// Each entity ID is unique to this run, so the lookup by entity ID alone
		// finds the intended row.
		p, err := store.LoadSAMLProvider(ctx, rf.f.pool, entity)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = rf.f.srv.issueSAMLAssertion(ctx, httptest.NewRequest(http.MethodGet, "/", nil),
			&saml.Validated{ACSURL: "https://sp.test/acs"},
			p, sid, rf.f.userID, rf.f.orgID)
		if !errors.Is(err, errSPNotUsable) {
			t.Errorf("an assertion for %s was not refused at the signing step: %v", entity, err)
		}
	}
}
