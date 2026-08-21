package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oauth"
	"signari.dev/engine/internal/tokens"
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

func TestExchangeAudienceMatchIsOptionalAndEnforcedWhenOn(t *testing.T) {
	setMatch := func(t *testing.T, f *tokenFixture, on bool) {
		t.Helper()
		if _, err := f.pool.Exec(context.Background(),
			`UPDATE core.clients SET exchange_requires_audience_match = $2
			 WHERE client_id = $1`, f.clientID, on); err != nil {
			t.Fatal(err)
		}
	}

	// A subject token addressed to somebody else entirely.
	subjectForAnother := func(t *testing.T, f *tokenFixture) string {
		t.Helper()
		k, err := f.srv.cfg.Keys.Active(keys.ES256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		raw, err := tokens.NewSigner(k).SignJSON(tokens.AccessTokenClaims{
			Issuer: f.srv.cfg.Issuer, Subject: f.userID,
			Audience: []string{"https://someone-else.example"},
			Expiry:   now.Add(time.Minute).Unix(), IssuedAt: now.Unix(),
			JTI: "audmatch-" + t.Name(), ClientID: "a-different-client",
			Scope: "openid",
		}, tokens.TypAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	t.Run("off by default: the exchange works", func(t *testing.T) {
		f := newTokenFixture(t)
		f.enableExchange(t)
		status, body := f.post(t, url.Values{
			"grant_type":         {oauth.GrantTypeTokenExchange},
			"client_secret":      {f.exchangeSecret},
			"subject_token":      {subjectForAnother(t, f)},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"client_id":          {f.clientID},
			"audience":           {exchangeAudience},
		})
		if status != http.StatusOK {
			t.Fatalf("an exchange that works today was refused with the setting off: "+
				"%d %v — the default must not change behaviour", status, body)
		}
	})

	t.Run("on: a token addressed elsewhere is refused", func(t *testing.T) {
		f := newTokenFixture(t)
		f.enableExchange(t)
		setMatch(t, f, true)
		status, body := f.post(t, url.Values{
			"grant_type":         {oauth.GrantTypeTokenExchange},
			"client_secret":      {f.exchangeSecret},
			"subject_token":      {subjectForAnother(t, f)},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"client_id":          {f.clientID},
			"audience":           {exchangeAudience},
		})
		if status == http.StatusOK {
			t.Fatal("a client exchanged a token it neither holds nor is named in " +
				"the audience of, with the containment switched on")
		}
		if !strings.Contains(asString(body["error_description"]), "audience") {
			t.Errorf("the refusal does not explain which rule refused it: %v", body)
		}
	})

	t.Run("on: the client's own token still exchanges", func(t *testing.T) {
		f := newTokenFixture(t)
		f.enableExchange(t)
		setMatch(t, f, true)
		subject := f.subjectTokenWithDetails(t,
			"verifier-audmatch-own-aaaaaaaaaaaaaaaaaaaaa", nil)
		status, body := f.post(t, url.Values{
			"grant_type":         {oauth.GrantTypeTokenExchange},
			"client_secret":      {f.exchangeSecret},
			"subject_token":      {subject},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"client_id":          {f.clientID},
			"audience":           {exchangeAudience},
		})
		if status != http.StatusOK {
			t.Fatalf("the holder of the subject token was refused by the audience "+
				"containment: %d %v", status, body)
		}
	})
}
