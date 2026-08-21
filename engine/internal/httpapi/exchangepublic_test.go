package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"signari.dev/engine/internal/oauth"
)

func TestAPublicClientCannotExchangeTokens(t *testing.T) {
	f := newTokenFixture(t)
	// Deliberately NOT enableExchange: that helper now makes the client
	// confidential, which is the only configuration in which exchange is
	// permitted. The point here is the configuration an operator can still
	// create by setting the flag directly on a public client.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET may_exchange = true, exchange_audiences = $2
		 WHERE client_id = $1`, f.clientID, []string{exchangeAudience}); err != nil {
		t.Fatal(err)
	}

	var kind string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT client_type FROM core.clients WHERE client_id = $1`, f.clientID).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "public" {
		t.Fatalf("the fixture client is %q, so this test is not exercising a "+
			"public client and proves nothing", kind)
	}

	subject := f.subjectTokenWithDetails(t,
		"verifier-exchange-public-aaaaaaaaaaaaaaaaaaa", nil)

	status, body := f.post(t, url.Values{
		"grant_type":         {oauth.GrantTypeTokenExchange},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {f.clientID},
		"audience":           {exchangeAudience},
	})

	if status == http.StatusOK {
		t.Fatalf("a PUBLIC client exchanged a token with no client authentication "+
			"and received %v. `may_exchange` on a public client cannot be enforced: "+
			"anyone holding the subject token can present it with this client_id",
			body["access_token"] != nil)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error is %v, want invalid_client — the refusal is about who the "+
			"caller is, not about the request", body["error"])
	}
}
