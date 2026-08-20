package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/tokens"
)

// openidToken mints a token that userinfo will actually honour.
//
// The fixture's own mintAccessToken produces a credential-endpoint token with no
// `openid` scope. Using it here made this test pass for the wrong reason: with
// the guard removed the query token WAS accepted, and the request then failed
// 403 insufficient_scope. The test caught the change and would not have caught
// the vulnerability.
func openidToken(t *testing.T, f *tokenFixture) string {
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
		JTI: "query-presentation-" + t.Name(), ClientID: f.clientID,
		Scope: "openid",
	}, tokens.TypAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// RFC 6750 §2.3, and the OpenID Foundation's OID4VCI issuer conformance plan
// runs this as `IssuerAccessTokenInQueryTest`.
//
//	"Because of the security weaknesses associated with the URI method... the
//	URI Query Parameter method SHOULD NOT be used unless it is impossible to
//	transport the access token in the "Authorization" request header field or
//	the HTTP request entity-body."
//
// A token in a query string is written to the far end's access log, to every
// proxy in between, and to browser history — and at a credential endpoint the
// token authorises minting a verifiable credential.
//
// This holds by construction: bearerTokenAndScheme reads r.PostForm, which
// excludes the URL query, and only when the content type is form-encoded. It had
// no test, and "correct by construction" survives exactly until somebody changes
// PostForm to Form — a one-word edit that reads like a simplification.
func TestAnAccessTokenInTheQueryStringIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	configureCredential(t, f)
	raw := openidToken(t, f)

	for _, tc := range []struct{ name, path, ctype, body string }{
		{
			name:  "credential endpoint, token in query",
			path:  oidcPathCredential + "?access_token=" + raw,
			ctype: "application/json",
			body:  `{"credential_configuration_id":"IdentityCredential"}`,
		},
		{
			name:  "userinfo, token in query",
			path:  "/oauth2/userinfo?access_token=" + raw,
			ctype: "application/x-www-form-urlencoded",
			body:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.ctype)
			rec := httptest.NewRecorder()
			f.srv.Routes().ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				t.Errorf("a token presented in the query string was accepted (%d). "+
					"It lands in access logs, proxies and browser history, and at "+
					"the credential endpoint it authorises minting a credential.",
					rec.Code)
			}
			// Specifically NOT counting an insufficient_scope 403 as success. A
			// refusal for an unrelated reason would let this test pass against a
			// server that honours query tokens perfectly well.
			if strings.Contains(rec.Header().Get("WWW-Authenticate"), "insufficient_scope") {
				t.Errorf("refused with insufficient_scope, which means the token WAS " +
					"read from the query string and failed a later check — this test " +
					"must fail when the query is read at all")
			}
		})
	}
}

// RFC 6750 §2: "Clients MUST NOT use more than one method to transmit the token
// in each request."
//
// Two presentations are ambiguous by construction — a server that picks one is
// choosing which of two credentials to honour, and an attacker who can add a
// body parameter to a request that already carries a header gets to make that
// choice for it.
func TestTwoTokenPresentationsAreRefused(t *testing.T) {
	f := newTokenFixture(t)
	raw := openidToken(t, f)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo",
		strings.NewReader("access_token="+raw))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("the same token presented twice — header and body — was accepted; " +
			"RFC 6750 §2 forbids more than one transmission method per request")
	}
}
