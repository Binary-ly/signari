package httpapi

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
	"signari.dev/engine/internal/uma"
)

// setSubject sets how a client names people, as every surface does.
func setSubject(t *testing.T, pool *pgxpool.Pool, clientID, kind, sector string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetClientSettings(ctx, tx, clientID, store.ClientSettings{SubjectType: &kind, Sector: &sector}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// pairwiseIn is the identifier a sector knows the fixture's person by. The rows go with
// the organisation's person, and the cleanup is for a test that leaves the person alone.
func (f *tokenFixture) pairwiseIn(t *testing.T, sector string) string {
	t.Helper()
	sub, err := store.PairwiseSubject(context.Background(), f.pool, f.orgID, sector, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	f.forgetPairwise(t)
	return sub
}

func (f *tokenFixture) forgetPairwise(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.pairwise_subjects WHERE org_id = $1::uuid`, f.orgID)
	})
}

// sibling is another confidential client of the fixture's organisation, which the same
// person signs in to in the same session.
func (f *tokenFixture) sibling(t *testing.T, suffix string) (*tokenFixture, string) {
	t.Helper()
	ctx := context.Background()
	other := *f
	other.clientID = f.clientID + suffix
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash,
		                          grant_types, scopes, require_pkce)
		VALUES ($1,$2,'S','confidential',$3, ARRAY['authorization_code','refresh_token'],
		        ARRAY['openid','offline_access'], true)`, other.clientID, f.orgID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO core.client_redirect_uris (client_id, redirect_uri) VALUES ($1,$2)`,
		other.clientID, "https://rp.test/cb"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, other.clientID)
	})
	return &other, secret
}

// signsIn redeems a code for the client and answers the tokens.
func (f *tokenFixture) signsIn(t *testing.T, secret string, scopes ...string) map[string]any {
	t.Helper()
	verifier := strings.Repeat("p", 48)
	form := f.redeem(f.issueCodeWithScopes(t, verifier, scopes), verifier)
	form.Set("client_secret", secret)
	status, body := f.post(t, form)
	if status != http.StatusOK {
		t.Fatalf("redeeming a code: %d %v", status, body)
	}
	return body
}

// userinfoSub is what userinfo says, and its status.
func (f *tokenFixture) userinfoSub(t *testing.T, token string) (int, any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, oidc.PathUserinfo, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out["sub"]
}

// A client set to pairwise, through a person's life with it (9.07): two sectors cannot
// compare notes, a sector's clients can, everything that names the person to the client
// agrees, and inside the engine the token still means the person.
func TestPairwiseSubjectsThroughTheirLife(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	f.forgetPairwise(t)
	secret := revocableClient(t, f)
	sameSector, sameSecret := f.sibling(t, "-same")
	elsewhere, elseSecret := f.sibling(t, "-else")
	public, publicSecret := f.sibling(t, "-public")

	set := func(clientID, kind, sector string) {
		t.Helper()
		setSubject(t, f.pool, clientID, kind, sector)
	}
	// Who the ID token and the access token say it is, which must be the same.
	sees := func(c *tokenFixture, secret string) string {
		t.Helper()
		body := c.signsIn(t, secret, "openid")
		id, access := claimsOfJWT(t, body["id_token"].(string))["sub"], claimsOfJWT(t, body["access_token"].(string))["sub"]
		if id != access {
			t.Fatalf("the ID token says %v and the access token %v", id, access)
		}
		return id.(string)
	}

	if got := sees(f, secret); got != f.userID {
		t.Fatalf("a client left alone sees %q, want the person's id", got)
	}

	set(f.clientID, "pairwise", "apps.example")
	set(sameSector.clientID, "pairwise", "apps.example")
	set(elsewhere.clientID, "pairwise", "elsewhere.example")

	sub := sees(f, secret)
	if !strings.HasPrefix(sub, store.PairwisePrefix) || strings.Contains(sub, f.userID) {
		t.Fatalf("a pairwise client sees %q", sub)
	}
	if got := sees(f, secret); got != sub {
		t.Errorf("signing in again gave %q, want %q", got, sub)
	}
	if got := sees(sameSector, sameSecret); got != sub {
		t.Errorf("a client of the same sector sees %q, want %q", got, sub)
	}
	if got := sees(elsewhere, elseSecret); got == sub || got == f.userID {
		t.Errorf("a client of another sector sees %q", got)
	}
	if got := sees(public, publicSecret); got != f.userID {
		t.Errorf("a public client sees %q", got)
	}

	// Everywhere it is said back, and through a refresh.
	body := f.signsIn(t, secret, "openid", "offline_access")
	access, refresh := body["access_token"].(string), body["refresh_token"].(string)
	if code, got := f.userinfoSub(t, access); code != http.StatusOK || got != sub {
		t.Errorf("userinfo: %d %v", code, got)
	}
	if got := f.introspect(t, access, f.clientID, secret); got["active"] != true || got["sub"] != sub {
		t.Errorf("introspecting an access token: %v", got)
	}
	if got := f.introspect(t, refresh, f.clientID, secret); got["active"] != true || got["sub"] != sub {
		t.Errorf("introspecting a refresh token: %v", got)
	}
	status, refreshed := f.post(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.clientID}, "client_secret": {secret}})
	if status != http.StatusOK {
		t.Fatalf("refreshing: %d %v", status, refreshed)
	}
	if got := claimsOfJWT(t, refreshed["access_token"].(string))["sub"]; got != sub {
		t.Errorf("a refreshed access token says %v", got)
	}
	if got := claimsOfJWT(t, refreshed["id_token"].(string))["sub"]; got != sub {
		t.Errorf("a refreshed ID token says %v", got)
	}

	// Inside, it is the person: this is the holder check reading core.users.
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'deactivated' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}
	if got := f.introspect(t, access, f.clientID, secret); got["active"] != false {
		t.Errorf("a deactivated person's token: %v", got)
	}
	if code, _ := f.userinfoSub(t, access); code == http.StatusOK {
		t.Error("userinfo took a deactivated person's token")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE core.users SET status = 'active' WHERE id = $1::uuid`, f.userID); err != nil {
		t.Fatal(err)
	}

	// A handle is a token like any other.
	opaque := "opaque"
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.SetClientSettings(ctx, tx, f.clientID, store.ClientSettings{AccessTokenFormat: &opaque}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	handle := f.signsIn(t, secret, "openid")["access_token"].(string)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.opaque_access_tokens WHERE client_id = $1`, f.clientID)
	})
	if got := f.introspect(t, handle, f.clientID, secret); got["active"] != true || got["sub"] != sub {
		t.Errorf("introspecting a handle: %v", got)
	}
	if code, got := f.userinfoSub(t, handle); code != http.StatusOK || got != sub {
		t.Errorf("userinfo with a handle: %d %v", code, got)
	}

	// Going back and forth loses nobody.
	set(f.clientID, "public", "")
	if code, got := f.userinfoSub(t, f.signsIn(t, secret, "openid")["access_token"].(string)); code != http.StatusOK || got != f.userID {
		t.Errorf("back to public: %d %v", code, got)
	}
	set(f.clientID, "pairwise", "")
	if got := claimsOfJWT(t, f.signsIn(t, secret, "openid")["id_token"].(string))["sub"]; got != sub {
		t.Errorf("pairwise again says %v, want %q", got, sub)
	}

	// With the person gone, what stood for them stands for nobody.
	if _, err := f.pool.Exec(ctx, `DELETE FROM core.pairwise_subjects WHERE subject = $1`, sub); err != nil {
		t.Fatal(err)
	}
	if got := f.introspect(t, access, f.clientID, secret); got["active"] != false {
		t.Errorf("a token standing for nobody introspected as %v", got)
	}
	if code, _ := f.userinfoSub(t, access); code == http.StatusOK {
		t.Error("userinfo took a token standing for nobody")
	}
}

// The front-channel ID token of a hybrid response is an ID token like any other, and
// the document says a client may ask for this.
func TestTheOtherPlacesAPairwiseSubjectIsSaid(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	f.forgetPairwise(t)
	setSubject(t, f.pool, f.clientID, "pairwise", "hybrid.example")
	sub := f.pairwiseIn(t, "hybrid.example")
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.srv.mintHybridIDToken(ctx, c, f.sid, "a-code", "a-nonce", f.srv.cfg.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if got := claimsOfJWT(t, raw)["sub"]; got != sub {
		t.Errorf("the hybrid ID token says %v, want %q", got, sub)
	}

	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var doc struct {
		Types []string `json:"subject_types_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(doc.Types, "public") || !slices.Contains(doc.Types, "pairwise") {
		t.Errorf("discovery says %v", doc.Types)
	}
}

// Two grants at once for somebody new get one subject between them. The first holds its
// row uncommitted, so the second has read nothing and runs into it, and waits; when the
// first commits it reads that row, where it would otherwise fail the sign-in.
func TestARaceForAPairwiseSubjectGivesOneSubject(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	f.forgetPairwise(t)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	first, err := store.PairwiseSubject(ctx, tx, f.orgID, "race.example", f.userID)
	if err != nil {
		t.Fatal(err)
	}

	type answer struct {
		sub string
		err error
	}
	second := make(chan answer, 1)
	go func() {
		sub, err := store.PairwiseSubject(ctx, f.pool, f.orgID, "race.example", f.userID)
		second <- answer{sub, err}
	}()
	select {
	case got := <-second:
		t.Fatalf("the second grant did not wait for the first: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-second; got.err != nil || got.sub != first {
		t.Errorf("the second grant got %+v, want %q", got, first)
	}
}

// Access tokens have one way out, which puts the subject as the client knows it. An ID
// token is signed where it is built, so a new place that builds one must say so: a
// Subject of anything but what subjectFor answered hands a client the person's id.
func TestEveryIDTokenNamesThePersonAsItsClientDoes(t *testing.T) {
	sites := 0
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "IDTokenClaims" {
				return true
			}
			sites++
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, _ := kv.Key.(*ast.Ident); key == nil || key.Name != "Subject" {
					continue
				}
				if value, _ := kv.Value.(*ast.Ident); value == nil || value.Name != "subject" {
					t.Errorf("%s builds an ID token whose Subject is not what subjectFor answered", p)
				}
			}
			return true
		})
	}
	if sites < 2 {
		t.Fatalf("found %d places that build an ID token; there were 2 when this was written", sites)
	}
}

// A request names a person as the client knows them, and it is the session's person
// who is compared, as that client knows them.
func TestARequestNamesAPersonAsItsClientKnowsThem(t *testing.T) {
	f := newSignInFixture(t)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.pairwise_subjects WHERE org_id = $1::uuid`, f.orgID)
	})
	cookie := f.signInAndReturnCookie(t)
	setSubject(t, f.pool, f.clientID, "pairwise", "")

	hint, _ := f.redeemPlain(t, f.authorizePlain(t, cookie))["id_token"].(string)
	sub, _ := claimsOfJWT(t, hint)["sub"].(string)
	if !strings.HasPrefix(sub, store.PairwisePrefix) {
		t.Fatalf("the ID token says %q", sub)
	}
	if q := redirected(t, f.authorizeWith(t, cookie, url.Values{"id_token_hint": {hint}, "prompt": {"none"}})); q.Get("code") == "" {
		t.Errorf("its own ID token as a hint got %v", q)
	}
	asked := func(subject string) url.Values {
		t.Helper()
		return redirected(t, f.authorizeWith(t, cookie, url.Values{"prompt": {"none"},
			"claims": {`{"id_token":{"sub":{"value":"` + subject + `"}}}`}}))
	}
	if q := asked(sub); q.Get("code") == "" {
		t.Errorf("asking for them by their subject got %v", q)
	}
	if q := asked(f.userID); q.Get("code") != "" {
		t.Error("a client that knows nothing of the person's id was answered for it")
	}
}

// What is sent to a client when something ends is in its name, whichever way it goes: a
// logout token addressed by subject, and an event on the client's stream.
func TestAClientHearsOfAnEndingInItsOwnName(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	secret := f.makePollStream(t)
	setSubject(t, f.pool, f.clientID, "pairwise", "hears.example")
	sub := f.pairwiseIn(t, "hears.example")
	if _, err := f.pool.Exec(ctx, `UPDATE core.clients SET backchannel_logout_uri = 'https://rp.test/logout'
		WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE payload->>'client_id' = $1`, f.clientID)
	})

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.TerminateSessions(ctx, tx, "", f.userID, store.ReasonAdminRevoke); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var notice string
	if err := f.pool.QueryRow(ctx, `SELECT payload->>'sub' FROM core.outbox
		WHERE topic = 'backchannel_logout' AND payload->>'client_id' = $1`, f.clientID).Scan(&notice); err != nil {
		t.Fatal(err)
	}
	if notice != sub {
		t.Errorf("the logout notice names %q, want %q", notice, sub)
	}

	code, resp := f.poll(t, secret, "")
	if code != http.StatusOK || len(resp.Sets) != 1 {
		t.Fatalf("polling: %d, %d events", code, len(resp.Sets))
	}
	for _, jws := range resp.Sets {
		raw, err := json.Marshal(setPayload(t, jws))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), sub) || strings.Contains(string(raw), f.userID) {
			t.Errorf("the event says %s, want the subject %q", raw, sub)
		}
	}
}

// A token exchanged into a pairwise client names the person as that client does, and the
// token it came from is read back on the way in, so it need not be the same one.
func TestAnExchangeNamesThePersonAsTheCallerKnowsThem(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	f.forgetPairwise(t)
	subject := f.subjectTokenWithDetails(t, strings.Repeat("x", 48), nil)
	exchange := func(token string) map[string]any {
		t.Helper()
		status, body := f.post(t, url.Values{"grant_type": {oauth.GrantTypeTokenExchange},
			"client_id": {f.clientID}, "client_secret": {f.exchangeSecret}, "subject_token": {token},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"audience":           {exchangeAudience}})
		if status != http.StatusOK {
			t.Fatalf("exchanging: %d %v", status, body)
		}
		return body
	}

	setSubject(t, f.pool, f.clientID, "pairwise", "exchange.example")
	sub := f.pairwiseIn(t, "exchange.example")
	into := exchange(subject)["access_token"].(string)
	if got := claimsOfJWT(t, into)["sub"]; got != sub {
		t.Errorf("exchanged in, the token says %v, want %q", got, sub)
	}
	if got := claimsOfJWT(t, exchange(into)["access_token"].(string))["sub"]; got != sub {
		t.Errorf("exchanged again, the token says %v, want %q", got, sub)
	}
}

// An actor is somebody too, so a person acting for another is named in both of a grant's
// tokens as the client knows them, and the actor a grant holds is not changed under it.
func TestAnActorIsNamedAsTheClientKnowsThem(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	f.forgetPairwise(t)
	secret := revocableClient(t, f)
	setSubject(t, f.pool, f.clientID, "pairwise", "actor.example")

	var actor string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'a'||substr(gen_random_uuid()::text,1,8)||'@example.test', sha256(gen_random_uuid()::text::bytea))
		RETURNING id::text`, f.orgID).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, actor)
	})
	if _, err := f.pool.Exec(ctx, `UPDATE core.sessions SET impersonator_id = $2::uuid WHERE sid = $1`, f.sid, actor); err != nil {
		t.Fatal(err)
	}
	body := f.signsIn(t, secret, "openid")
	for name, raw := range map[string]string{"ID": body["id_token"].(string), "access": body["access_token"].(string)} {
		act, _ := claimsOfJWT(t, raw)["act"].(map[string]any)
		got, _ := act["sub"].(string)
		if !strings.HasPrefix(got, store.PairwisePrefix) {
			t.Errorf("the %s token's act says %v", name, act)
		}
	}

	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	given := &tokens.Actor{Subject: actor, Act: &tokens.Actor{Subject: "a-workload"}}
	named, err := actorFor(ctx, f.pool, c, given)
	if err != nil {
		t.Fatal(err)
	}
	if given.Subject != actor || named.Subject == actor || named.Act.Subject != "a-workload" {
		t.Errorf("given %+v, named %+v", given, named)
	}
}

// An ID token a pairwise client pushes as a claim token identifies the person, not a
// stranger with a strange name.
func TestAPairwiseClaimTokenIdentifiesTheRequestingParty(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()
	f.allowUserOn(t, "document", "42", "viewer", f.email)
	setSubject(t, f.pool, f.clientID, "pairwise", "uma.example")
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.pairwise_subjects WHERE org_id = $1::uuid`, f.orgID)
	})
	sub, err := store.PairwiseSubject(ctx, f.pool, f.orgID, "uma.example", f.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, body := f.permission(t, f.clientID, f.secret, onePermission)
	ticket, _ := body["ticket"].(string)
	code, body := f.exchange(t, f.clientID, ticket, url.Values{
		"claim_token": {f.idTokenFor(t, sub, f.clientID, time.Hour)}, "claim_token_format": {uma.ClaimTokenFormatIDToken}})
	if code != http.StatusOK {
		t.Fatalf("pushing a pairwise ID token: %d %v", code, body)
	}
	rpt, _ := body["access_token"].(string)
	if got := claimsOfJWT(t, rpt)["sub"]; got != sub {
		t.Errorf("the RPT says %v, want %q", got, sub)
	}
}

// A Txn-Token names its subject by the id the deployment's workloads share, which a
// pairwise client is set up never to see.
func TestAPairwiseClientIsGivenNoTxnTokenNamingAPerson(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	f.forgetPairwise(t)
	subject := f.mintAccessTokenWithScope(t, []string{"read"})
	const accessToken = "urn:ietf:params:oauth:token-type:access_token"
	if status, body := f.txnToken(t, subject, accessToken, "read"); status != http.StatusOK {
		t.Fatalf("before: %d %v", status, body)
	}
	setSubject(t, f.pool, f.clientID, "pairwise", "txn.example")
	status, body := f.txnToken(t, subject, accessToken, "read")
	if status != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Errorf("after: %d %v", status, body)
	}
}

// A credential goes to verifiers this deployment never meets, so it says what the client
// it was issued through says.
func TestACredentialNamesThePersonAsItsClientDoes(t *testing.T) {
	f := newTokenFixture(t)
	f.forgetPairwise(t)
	f.allowPreAuthGrant(t)
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.credential_configurations
			(org_id, config_id, vct, always_claims, selective_claims, lifetime, display_name)
		VALUES ($1::uuid, 'TestCredential', 'https://signari.test/test',
		        ARRAY['sub'], ARRAY['email'], interval '30 days', 'Test')`, f.orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.credential_configurations WHERE org_id = $1::uuid`, f.orgID)
	})
	setSubject(t, f.pool, f.clientID, "pairwise", "wallet.example")
	sub := f.pairwiseIn(t, "wallet.example")

	status, body := f.post(t, preAuthForm(f.preAuth(t, "", 5*time.Minute), ""))
	if status != http.StatusOK {
		t.Fatalf("redemption gave %d: %v", status, body)
	}
	token := asString(body["access_token"])
	wa := newWallet(t)
	_, nb := f.postJSON(t, "/oid4vci/nonce", "", "")
	nonce, _ := nb["c_nonce"].(string)
	status, resp := f.postJSON(t, "/oid4vci/credential", token,
		`{"credential_configuration_id":"TestCredential","proofs":{"jwt":[`+
			mustJSONString(t, wa.proof(t, f.srv.cfg.Issuer, nonce))+`]}}`)
	if status != http.StatusOK {
		t.Fatalf("the credential: %d %v", status, resp)
	}
	creds, _ := resp["credentials"].([]any)
	first, _ := creds[0].(map[string]any)
	credential, _ := first["credential"].(string)
	issued, _, _ := strings.Cut(credential, "~")
	if got := claimsOfJWT(t, issued)["sub"]; got != sub {
		t.Errorf("the credential says %v, want %q", got, sub)
	}
}
