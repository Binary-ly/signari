package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tokens"
)

// RFC 8693 §4.4 enforced through the real token endpoint.
//
// The unit tests in internal/oauth prove CheckMayAct decides correctly. They
// cannot prove it is reached with the right data — which is exactly the shape of
// the WebAuthn defect found earlier this session, where a correct function was
// fed a credential nobody had finished loading.
//
// So this drives POST /oauth2/token with a real subject token carrying may_act.
func TestMayActIsEnforcedAtTheTokenEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	// Confidential, because token exchange is not available to a public client:
	// `may_exchange` says "this client may act for that user", and a public
	// client cannot prove it is that client.
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients
		   SET may_exchange = true,
		       exchange_audiences = ARRAY['https://api.example'],
		       client_type = 'confidential', client_secret_hash = $2,
		       grant_types = grant_types || ARRAY['urn:ietf:params:oauth:grant-type:token-exchange']
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret

	mint := func(t *testing.T, mayAct map[string]any) string {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.userID,
			Audience: []string{f.clientID},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: "mayact-" + t.Name(), ClientID: f.clientID,
			Scope: "openid", MayAct: mayAct,
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	exchange := func(t *testing.T, subjectToken string) (int, map[string]any) {
		t.Helper()
		form := strings.NewReader(
			"grant_type=urn:ietf:params:oauth:grant-type:token-exchange" +
				"&subject_token=" + subjectToken +
				"&subject_token_type=urn:ietf:params:oauth:token-type:access_token" +
				"&audience=https://api.example" +
				"&client_id=" + f.clientID +
				"&client_secret=" + f.exchangeSecret)
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	t.Run("may_act naming another client refuses the exchange", func(t *testing.T) {
		code, body := exchange(t, mint(t, map[string]any{"client_id": "somebody-else"}))
		if code == http.StatusOK {
			t.Fatalf("the exchange succeeded despite may_act naming another client: %v", body)
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "may_act") {
			t.Errorf("the refusal does not mention may_act, so it may be for an "+
				"unrelated reason: %d %v", code, body)
		}
	})

	t.Run("a may_act member we cannot evaluate refuses", func(t *testing.T) {
		code, body := exchange(t, mint(t, map[string]any{
			"client_id": f.clientID, "department": "finance"}))
		if code == http.StatusOK {
			t.Fatalf("an unevaluable may_act member was ignored: %v", body)
		}
		desc, _ := body["error_description"].(string)
		if !strings.Contains(desc, "department") {
			t.Errorf("the refusal should name the member: %v", body)
		}
	})

	// The control: without may_act the exchange must still work, or this is not
	// an enforcement, it is an outage.
	t.Run("no may_act leaves the exchange working", func(t *testing.T) {
		code, body := exchange(t, mint(t, nil))
		if code != http.StatusOK {
			t.Fatalf("an ordinary exchange was refused: %d %v", code, body)
		}
		if body["access_token"] == nil {
			t.Errorf("no access_token in the response: %v", body)
		}
	})
}

// RFC 8693 §4.4 defines `may_act` as naming the party authorized TO ACT:
//
//	"A claim whose value is a JSON object containing a member ... identifying
//	some party that is authorized to become the actor and act on behalf of the
//	subject." ... "The claims within the may_act claim pertain only to the
//	identity of that party."
//
// So `may_act.sub` is the ACTOR's subject. We passed the SUBJECT token's own
// `sub` into that comparison — the user being acted *for*, not the party doing
// the acting. Two consequences, and the second is the dangerous one:
//
//   - `may_act: {"sub": "bob"}` on Alice's token can never be satisfied, because
//     the value compared is always Alice. The constraint reads as permanently
//     unsatisfiable rather than as one this server cannot evaluate.
//   - `may_act: {"sub": "<alice>"}` on Alice's own token — "only Alice herself
//     may act" — compares alice against alice and **passes**. The restriction is
//     honoured vacuously, and any client with `may_exchange` may exchange the
//     token while the issuer believes delegation was pinned to one person.
//
// The second is a false pass on a real constraint, which is the same failure
// class this file's header objects to: a restriction the issuer placed in a
// signed token, not applied by the receiver.
//
// Without an `actor_token`, the acting party is a CLIENT and has no user
// subject. There is nothing correct to compare `may_act.sub` against, so it must
// be refused as unevaluable — the policy `CheckMayAct` already applies to members
// it does not understand.
func TestMayActSubIsAboutTheActorNotTheSubject(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients
		   SET may_exchange = true,
		       exchange_audiences = ARRAY['https://api.example'],
		       client_type = 'confidential', client_secret_hash = $2,
		       grant_types = grant_types || ARRAY['urn:ietf:params:oauth:grant-type:token-exchange']
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret

	mint := func(t *testing.T, mayAct map[string]any) string {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.userID,
			Audience: []string{f.clientID},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: "mayactsub-" + t.Name(), ClientID: f.clientID,
			Scope: "openid", MayAct: mayAct,
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	exchange := func(t *testing.T, subjectToken string) (int, map[string]any) {
		t.Helper()
		form := strings.NewReader(
			"grant_type=urn:ietf:params:oauth:grant-type:token-exchange" +
				"&subject_token=" + subjectToken +
				"&subject_token_type=urn:ietf:params:oauth:token-type:access_token" +
				"&audience=https://api.example" +
				"&client_id=" + f.clientID +
				"&client_secret=" + f.exchangeSecret)
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	// "Only this person may act for this person." No actor_token is presented, so
	// the acting party is a client and the constraint cannot be evaluated.
	code, body := exchange(t, mint(t, map[string]any{"sub": f.userID}))
	if code == http.StatusOK {
		t.Fatalf("a subject token restricting delegation to sub=%q was exchanged by "+
			"a client presenting no actor_token. The comparison used the subject's "+
			"own sub, so the restriction matched itself and was honoured vacuously",
			f.userID)
	}
	if !strings.Contains(asString(body["error_description"]), "sub") {
		t.Errorf("the refusal does not mention the member it could not evaluate: %v", body)
	}
}

func TestDelegationThroughAnActorToken(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()

	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.clients
		   SET may_exchange = true,
		       exchange_audiences = ARRAY['https://api.example'],
		       client_type = 'confidential', client_secret_hash = $2,
		       grant_types = grant_types || ARRAY['urn:ietf:params:oauth:grant-type:token-exchange']
		 WHERE client_id = $1`, f.clientID, hash); err != nil {
		t.Fatal(err)
	}
	f.exchangeSecret = secret

	// The delegate: a second user, whose token is the actor token.
	var actorID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, username, user_handle, migration_state)
		VALUES ($1::uuid, 'delegate-'||substr(md5(random()::text),1,8),
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'),
		        'complete')
		RETURNING id::text`, f.orgID).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.users WHERE id = $1::uuid`, actorID)
	})

	mint := func(t *testing.T, sub string, mayAct map[string]any, jti string) string {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: sub,
			Audience: []string{f.clientID},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: jti, ClientID: f.clientID, Scope: "openid", MayAct: mayAct,
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	exchange := func(t *testing.T, subjectToken, actorToken string) (int, map[string]any) {
		t.Helper()
		body := "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" +
			"&subject_token=" + subjectToken +
			"&subject_token_type=urn:ietf:params:oauth:token-type:access_token" +
			"&audience=https://api.example" +
			"&client_id=" + f.clientID +
			"&client_secret=" + f.exchangeSecret
		if actorToken != "" {
			body += "&actor_token=" + actorToken +
				"&actor_token_type=urn:ietf:params:oauth:token-type:access_token"
		}
		req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	t.Run("the named delegate may act", func(t *testing.T) {
		subject := mint(t, f.userID, map[string]any{"sub": actorID}, "d-subj-1")
		actor := mint(t, actorID, nil, "d-actor-1")
		code, body := exchange(t, subject, actor)
		if code != http.StatusOK {
			t.Fatalf("the delegate named in may_act was refused: %d %v", code, body)
		}
		at := asString(body["access_token"])
		if at == "" {
			t.Fatalf("no access token: %v", body)
		}
		// §4.1: the issued token records who acted.
		claims := decodeJWTPayload(t, at)
		act, _ := claims["act"].(map[string]any)
		if act == nil || act["sub"] != actorID {
			t.Errorf("act = %v, want sub = %q — the audit trail must name the "+
				"party that acted, not only the client that called", act, actorID)
		}
	})

	t.Run("somebody else may not", func(t *testing.T) {
		subject := mint(t, f.userID, map[string]any{"sub": "not-this-person"}, "d-subj-2")
		actor := mint(t, actorID, nil, "d-actor-2")
		code, body := exchange(t, subject, actor)
		if code == http.StatusOK {
			t.Fatal("an actor the subject token did not name was allowed to act")
		}
		if !strings.Contains(asString(body["error_description"]), "may_act") {
			t.Errorf("the refusal does not name may_act: %v", body)
		}
	})

	t.Run("an invalid actor token is refused", func(t *testing.T) {
		subject := mint(t, f.userID, map[string]any{"sub": actorID}, "d-subj-3")
		code, body := exchange(t, subject, "not.a.token")
		if code == http.StatusOK {
			t.Fatal("a malformed actor token was accepted; §2.1 requires the actor " +
				"token to be validated too")
		}
		if !strings.Contains(asString(body["error_description"]), "actor token") {
			t.Errorf("the refusal does not say the ACTOR token was the problem: %v", body)
		}
	})
}
