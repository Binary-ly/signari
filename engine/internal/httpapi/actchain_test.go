package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// RFC 8693 §4.1, the structural property of the actor claim:
//
//	"A chain of delegation can be expressed by nesting one 'act' claim within
//	another. The outermost 'act' claim represents the current actor while nested
//	'act' claims represent prior actors. The least recent actor is the most
//	deeply nested."
//
// `tokens.Actor` models exactly that — `{Subject string; Act *Actor}` — and
// `handleTokenExchange` builds `act = {sub: caller, act: prior}`. What was
// untested is whether a chain of two hops comes out in the right ORDER, which is
// the only thing the nesting is for: §4.1 also says a consumer "MUST only
// consider the token's top-level claims and the party identified as the current
// actor", so which end of the chain is current decides who is authorised.
//
// A chain built the other way round would look identical in every single-hop
// test and name the wrong party as current in every multi-hop one.

// secondExchangeClient registers another client permitted to exchange.
// secondExchangeClient is a second client permitted to exchange, so the actor
// chain has more than one link.
//
// Confidential, like the fixture: token exchange is not available to a public
// client, which cannot prove it is the client the permission was granted to.
func secondExchangeClient(t *testing.T, f *tokenFixture) (string, string) {
	t.Helper()
	id := f.clientID + "-b"
	ctx := context.Background()
	secret, hash := newTestSecret(t)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes,
		                          require_pkce, may_exchange, exchange_audiences)
		VALUES ($1,$2,'B','confidential',$4, ARRAY['authorization_code','refresh_token'],
		        ARRAY['openid','offline_access'], true, true, $3)`,
		id, f.orgID, []string{exchangeAudience}, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.clients WHERE client_id = $1`, id)
	})
	return id, secret
}

func TestTheActorChainNestsOldestDeepest(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	clientB, clientBSecret := secondExchangeClient(t, f)

	subject := f.mintAccessTokenWithScope(t, []string{"read"})

	// Each client authenticates as itself: the whole point of the chain is that
	// the parties are distinct, so they cannot share a secret.
	exchange := func(token, asClient, asSecret string) string {
		t.Helper()
		status, body := f.post(t, url.Values{
			"grant_type":         {oauth.GrantTypeTokenExchange},
			"client_secret":      {asSecret},
			"subject_token":      {token},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"audience":           {exchangeAudience},
			"scope":              {"read"},
			"client_id":          {asClient},
		})
		if status != http.StatusOK {
			t.Fatalf("exchange as %s gave %d: %v", asClient, status, body)
		}
		out, _ := body["access_token"].(string)
		if out == "" {
			t.Fatalf("no access_token in %v", body)
		}
		return out
	}

	// Hop one: the fixture's client acts for the subject.
	first := exchange(subject, f.clientID, f.exchangeSecret)
	claims := decodeJWTPayload(t, first)

	act, ok := claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("the exchanged token carries no act claim, so a resource server "+
			"cannot tell it was obtained by exchange rather than issued to the "+
			"subject directly: %v", claims)
	}
	if act["sub"] != f.clientID {
		t.Errorf("act.sub = %v, want the exchanging client %q", act["sub"], f.clientID)
	}
	if _, nested := act["act"]; nested {
		t.Errorf("a first exchange produced a nested act: %v", act)
	}

	// Hop two: a different client exchanges the result.
	second := exchange(first, clientB, clientBSecret)
	claims = decodeJWTPayload(t, second)

	act, ok = claims["act"].(map[string]any)
	if !ok {
		t.Fatalf("the second exchange dropped the act claim: %v", claims)
	}
	// The CURRENT actor is outermost.
	if act["sub"] != clientB {
		t.Errorf("the outermost act.sub is %v; §4.1 makes it the CURRENT actor, "+
			"which is %q. A consumer applying access control reads this one",
			act["sub"], clientB)
	}
	// The prior actor is nested inside it.
	prior, ok := act["act"].(map[string]any)
	if !ok {
		t.Fatalf("the second exchange did not nest the first actor, so the "+
			"delegation history stops at one hop: %v", act)
	}
	if prior["sub"] != f.clientID {
		t.Errorf("the nested act.sub is %v, want the earlier actor %q",
			prior["sub"], f.clientID)
	}
	// And no third level appeared from nowhere.
	if _, tooDeep := prior["act"]; tooDeep {
		t.Errorf("a two-hop chain produced three levels: %v", act)
	}

	// The subject is unchanged throughout: exchange delegates, it does not
	// rewrite who the token is about.
	if claims["sub"] == nil || claims["sub"] == clientB {
		t.Errorf("sub = %v after two exchanges; the token is still about the "+
			"original subject", claims["sub"])
	}
}
