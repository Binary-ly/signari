package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/oidc"
)

func (c *signingClient) assertionFrom(t *testing.T, key *ecdsa.PrivateKey, subject string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"iss": subject, "sub": subject, "aud": c.srv.cfg.Issuer,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("assertion-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "good"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// RFC 7523 §3 makes the assertion's subject the client, and §2.2's example of client
// authentication sends no `client_id`. One that did the same was told it was unknown.
func TestAnAssertionSaysWhichClientItIsFrom(t *testing.T) {
	c := newSigningClient(t)
	if _, err := c.pool.Exec(context.Background(), `UPDATE core.clients SET client_type = 'confidential',
		token_endpoint_auth_method = 'private_key_jwt' WHERE client_id = $1`, c.clientID); err != nil {
		t.Fatal(err)
	}
	cookie := c.signInAndReturnCookie(t)
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		c.srv.Routes().ServeHTTP(rec, req)
		return rec
	}
	redeem := func(assertion string, extra url.Values) *httptest.ResponseRecorder {
		t.Helper()
		loc, err := url.Parse(c.authorizeWith(t, cookie, nil).Header().Get("Location"))
		if err != nil || loc.Query().Get("code") == "" {
			t.Fatalf("no code: %q (%v)", loc, err)
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
			"redirect_uri": {"https://rp.test/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
			"client_assertion_type": {clientauth.AssertionType}, "client_assertion": {assertion}}
		for name, values := range extra {
			form[name] = values
		}
		return post(oidc.PathToken, form)
	}

	if rec := redeem(c.assertionFrom(t, c.key, c.clientID), nil); rec.Code != http.StatusOK {
		t.Errorf("an assertion with no client_id beside it answered %d %.200s", rec.Code, rec.Body)
	}

	// It names whose keys to try, and proves nothing until they verify it.
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		assertion string
		extra     url.Values
	}{
		"signed by somebody else": {c.assertionFrom(t, stranger, c.clientID), nil},
		"naming nobody":           {c.assertionFrom(t, c.key, "nobody-registered"), nil},
		"not a JWT":               {"not.a.jwt", nil},
		"another client beside it": {c.assertionFrom(t, c.key, c.clientID),
			url.Values{"client_id": {"nobody-registered"}}},
	} {
		if rec := redeem(tc.assertion, tc.extra); rec.Code != http.StatusUnauthorized ||
			!strings.Contains(rec.Body.String(), "invalid_client") {
			t.Errorf("%s answered %d %.200s", name, rec.Code, rec.Body)
		}
	}

	// The same resolver at the other endpoints a client calls, and a push has to come
	// out usable: the handle is asked for by client_id, and it was pushed without one.
	form, err := url.ParseQuery(c.plainAuthz())
	if err != nil {
		t.Fatal(err)
	}
	form.Del("client_id")
	form.Set("client_assertion_type", clientauth.AssertionType)
	form.Set("client_assertion", c.assertionFrom(t, c.key, c.clientID))
	pushed := post("/oauth2/par", form)
	var out struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(pushed.Body.Bytes(), &out); err != nil || out.RequestURI == "" {
		t.Fatalf("the push answered %d %.200s", pushed.Code, pushed.Body)
	}
	if arrived := c.byHandle(t, cookie, out.RequestURI); !strings.Contains(arrived.Header().Get("Location"), "code=") {
		t.Errorf("the handle answered %d %q", arrived.Code, arrived.Header().Get("Location"))
	}
}
