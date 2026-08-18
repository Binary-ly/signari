package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"signari.dev/engine/internal/oid4vci"
	"signari.dev/engine/internal/store"
)

// The OID4VCI pre-authorized code grant at the token endpoint.
//
// internal/oid4vci proves the RULES in isolation and internal/store proves the
// storage. What is untested until here is the wiring: whether the token endpoint
// dispatches to them, in the order that makes a wrong transaction code cost an
// attempt rather than the offer, and whether a wallet that sends no client_id at
// all -- the ordinary case, per §6.1 -- gets a token.

// preAuth plants an offer the way `signari credential offer` would.
func (f *tokenFixture) preAuth(t *testing.T, txCode string, ttl time.Duration) string {
	t.Helper()
	ctx := context.Background()

	code, hash, err := store.NewPreAuthCode()
	if err != nil {
		t.Fatal(err)
	}
	var tx *oid4vci.TxCode
	var txHash []byte
	if txCode != "" {
		tx = &oid4vci.TxCode{InputMode: oid4vci.InputNumeric, Length: len(txCode)}
		txHash = store.HashToken(txCode)
	}
	if err := store.NewPreAuthorizedCode(ctx, f.pool, f.orgID, f.userID, f.clientID,
		hash, []string{"TestCredential"}, tx, txHash, ttl); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = f.pool.Exec(c, `DELETE FROM core.preauthorized_codes WHERE code_hash = $1`, hash)
	})
	return code
}

// allowPreAuthGrant registers the fixture client for the grant.
//
// Separate from the fixture so the ungated case can be tested too: a client that
// is merely registered must NOT be able to redeem an offer.
func (f *tokenFixture) allowPreAuthGrant(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET grant_types = grant_types || $2::text WHERE client_id = $1`,
		f.clientID, oid4vci.GrantType); err != nil {
		t.Fatal(err)
	}
}

func preAuthForm(code, txCode string) url.Values {
	v := url.Values{
		"grant_type":          {oid4vci.GrantType},
		"pre-authorized_code": {code},
	}
	if txCode != "" {
		v.Set("tx_code", txCode)
	}
	return v
}

// THE case §6.1 describes: a wallet redeems sending no client_id.
//
// "the client_id parameter is only needed when a form of Client Authentication
// that relies on this parameter is used" -- and this grant uses none. A token
// endpoint that resolves the client from the request before dispatching refuses
// this as invalid_client, which is refusing the ordinary case while appearing to
// support the grant.
func TestAWalletRedeemsWithoutSendingAnyClientID(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)

	status, body := f.post(t, preAuthForm(code, ""))
	if status != http.StatusOK {
		t.Fatalf("anonymous redemption gave %d: %v", status, body)
	}
	at := asString(body["access_token"])
	if at == "" {
		t.Fatalf("no access token in the response: %v", body)
	}

	// The token is about the HOLDER and for the client the OFFER named, since
	// the request named nobody. A `sub` of anything else means the subject was
	// invented; an `aud` of anything else means the audience was.
	claims := claimsOfJWT(t, at)
	if claims["sub"] != f.userID {
		t.Errorf("sub is %v, want the credential subject %s", claims["sub"], f.userID)
	}
	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != f.clientID {
		t.Errorf("aud is %v, want [%s] from the offer", claims["aud"], f.clientID)
	}

	// No id_token: nothing here authenticated anybody. The operator vouched for
	// the holder when the offer was minted, at some earlier time, by some means
	// this server never saw -- so an id_token would assert an auth_time and an
	// amr that did not happen.
	if body["id_token"] != nil {
		t.Error("an id_token was issued for a grant with no authentication event")
	}
	// No refresh token: a refresh family is anchored to a session so that ending
	// the session ends the tokens, and there is no session here.
	if body["refresh_token"] != nil {
		t.Error("a refresh token was issued with no session to revoke it with")
	}
}

// claimsOfJWT decodes a signed token's payload WITHOUT verifying it.
//
// Only ever used to assert what a token this same server just minted says. A
// verifying read belongs in the token tests; here the signature is not the
// question, the claims are.
func claimsOfJWT(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// Single use, §3.5. The second redemption of the same code gets nothing.
func TestAPreAuthorizedCodeIsSpentByItsFirstRedemption(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)

	if status, body := f.post(t, preAuthForm(code, "")); status != http.StatusOK {
		t.Fatalf("first redemption gave %d: %v", status, body)
	}
	status, body := f.post(t, preAuthForm(code, ""))
	if status == http.StatusOK {
		t.Fatal("the same pre-authorized code was redeemed twice")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("second redemption gave error %v, want invalid_grant", body["error"])
	}
}

// A wrong transaction code must NOT spend the offer.
//
// This is the ordering the whole handler is arranged around. Claiming the code
// before comparing the transaction code would mean one wrong guess -- by anybody
// who photographed the QR code, which is the attacker §3.5 names -- destroys the
// holder's credential. A shoulder-surfing defence that a shoulder-surfer can
// turn into a denial of service is worse than none, because it looks like one.
func TestAWrongTransactionCodeCostsAnAttemptNotTheOffer(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "424242", 5*time.Minute)

	status, body := f.post(t, preAuthForm(code, "000000"))
	if status == http.StatusOK {
		t.Fatal("a wrong transaction code was accepted")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error %v, want invalid_grant", body["error"])
	}

	// The decisive assertion: the holder can still redeem.
	status2, body2 := f.post(t, preAuthForm(code, "424242"))
	if status2 != http.StatusOK {
		t.Fatalf("the offer was destroyed by somebody else's wrong guess: %d %v",
			status2, body2)
	}
}

// Five wrong guesses end the offer, and the SIXTH attempt fails even though it
// carries the right code.
//
// The limit is per code, not per address: an attacker guessing a transaction
// code is attacking one offer, so an address-keyed limit lets them change
// address while a code-keyed one ends the thing being attacked.
func TestGuessingTheTransactionCodeEndsTheOfferAtTheEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "424242", 5*time.Minute)

	for i := 0; i < oid4vci.MaxTxCodeAttempts; i++ {
		if status, _ := f.post(t, preAuthForm(code, "000000")); status == http.StatusOK {
			t.Fatalf("attempt %d: a wrong transaction code was accepted", i+1)
		}
	}
	status, body := f.post(t, preAuthForm(code, "424242"))
	if status == http.StatusOK {
		t.Fatal("the correct transaction code still worked after the attempt limit")
	}
	if !strings.Contains(strings.ToLower(asString(body["error_description"])), "attempt") {
		t.Errorf("the refusal does not mention the attempt limit: %v", body)
	}
}

// §6.1: tx_code "MUST be present if a tx_code object was present in the
// Credential Offer". An offer that asked for one is not redeemable without it.
func TestAnOfferRequiringATransactionCodeRefusesARequestWithout(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "424242", 5*time.Minute)

	status, body := f.post(t, preAuthForm(code, ""))
	if status == http.StatusOK {
		t.Fatal("an offer requiring a transaction code was redeemed without one")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error %v, want invalid_grant", body["error"])
	}

	// And the offer survives, for the same reason a wrong code does not spend
	// it: a wallet that forgot the parameter must not cost the holder anything.
	if status2, body2 := f.post(t, preAuthForm(code, "424242")); status2 != http.StatusOK {
		t.Fatalf("the offer was spent by a request that omitted tx_code: %d %v",
			status2, body2)
	}
}

// The converse, also §6.1: a transaction code sent for an offer that never asked
// for one means the wallet and the issuer disagree about what this offer is.
func TestATransactionCodeArrivingUnaskedIsRefusedAtTheEndpoint(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)

	if status, _ := f.post(t, preAuthForm(code, "424242")); status == http.StatusOK {
		t.Fatal("a transaction code was accepted for an offer that declared none")
	}
}

// §3.5: the code "MUST be short lived". An expired one is refused.
func TestAnExpiredPreAuthorizedCodeIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", -time.Second)

	if status, _ := f.post(t, preAuthForm(code, "")); status == http.StatusOK {
		t.Fatal("an expired pre-authorized code was redeemed")
	}
}

// A wallet that DOES send client_id must send the right one.
//
// §6.1 makes the parameter unnecessary, not free. A request naming a different
// client than the offer was issued to means the two disagree about what is being
// redeemed, and proceeding resolves that silently in the offer's favour.
func TestARedemptionNamingTheWrongClientIsRefused(t *testing.T) {
	f := newTokenFixture(t)
	f.allowPreAuthGrant(t)
	code := f.preAuth(t, "", 5*time.Minute)

	form := preAuthForm(code, "")
	form.Set("client_id", f.clientID+"-somebody-else")
	if status, _ := f.post(t, form); status == http.StatusOK {
		t.Fatal("an offer was redeemed while naming a different client")
	}

	// Naming the right one is fine, and still works.
	ok := preAuthForm(code, "")
	ok.Set("client_id", f.clientID)
	if status, body := f.post(t, ok); status != http.StatusOK {
		t.Fatalf("naming the correct client was refused: %d %v", status, body)
	}
}

// RFC 6749 §5.2: `unauthorized_client` is "The authenticated client is not
// authorized to use this authorization grant type."
//
// The fixture client is registered for authorization_code and refresh_token
// only, which is the column default. Merely existing must not be enough.
func TestAClientNotRegisteredForTheGrantCannotRedeemAnOffer(t *testing.T) {
	f := newTokenFixture(t)
	code := f.preAuth(t, "", 5*time.Minute) // no allowPreAuthGrant

	status, body := f.post(t, preAuthForm(code, ""))
	if status == http.StatusOK {
		t.Fatal("a client not registered for the grant redeemed an offer")
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error %v, want unauthorized_client", body["error"])
	}
}

// The same rule for the DEVICE grant, which had no such check at all.
//
// Any registered client could poll a device code whatever it was registered for.
// Kept here beside the OID4VCI cases because the two share the gate, and the
// missing one was found while adding the other.
func TestAClientNotRegisteredForTheDeviceGrantIsRefused(t *testing.T) {
	f := newTokenFixture(t)

	status, body := f.post(t, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"whatever"},
		"client_id":   {f.clientID},
	})
	if status == http.StatusOK {
		t.Fatal("a client not registered for the device grant was served")
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error %v, want unauthorized_client -- the grant gate is not "+
			"reached, so the device code is being looked up first: %v",
			body["error"], body)
	}
}

// And the positive half: with the grant registered, the refusal is about the
// device code rather than the client.
//
// Without this the gate could be refusing everything -- a test that only asserts
// a refusal cannot tell a working check from a broken handler.
func TestAClientRegisteredForTheDeviceGrantGetsPastTheGate(t *testing.T) {
	f := newTokenFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.clients SET grant_types = grant_types || $2::text WHERE client_id = $1`,
		f.clientID, "urn:ietf:params:oauth:grant-type:device_code"); err != nil {
		t.Fatal(err)
	}

	status, body := f.post(t, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"no-such-code"},
		"client_id":   {f.clientID},
	})
	if status == http.StatusOK {
		t.Fatal("an unknown device code was served a token")
	}
	if body["error"] == "unauthorized_client" {
		t.Fatal("the grant gate still refuses a client registered for the grant")
	}
	// `expired_token` is the deliberate answer to an unknown device code: the
	// handler gives unknown, expired and already-redeemed one indistinguishable
	// reply rather than a taxonomy a poller could use to probe for live codes.
	// What matters here is only that the answer is about the CODE.
	if body["error"] != "expired_token" {
		t.Errorf("error %v, want the device handler's answer for an unknown code",
			body["error"])
	}
}

// The device AUTHORIZATION endpoint needs its own gate, and this is the test
// that proves it has one.
//
// Written after removing the token-endpoint gate failed a test while removing
// this one failed nothing -- so the check existed and was believed rather than
// exercised. The two are not interchangeable: a client refused only at the token
// endpoint can still obtain a user code and put it in front of a person to
// approve, and the verification screen is where a device flow's phishing value
// actually is.
func TestAClientNotRegisteredForTheDeviceGrantCannotStartOne(t *testing.T) {
	f := newTokenFixture(t)

	form := url.Values{"client_id": {f.clientID}, "scope": {"openid"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code == http.StatusOK {
		t.Fatalf("a client not registered for the device grant started one: %v", body)
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error %v, want unauthorized_client: %v", body["error"], body)
	}
	// And nothing was handed out. A refusal that still mints a user code would
	// leave a code somebody could be talked into approving.
	if body["user_code"] != nil || body["device_code"] != nil {
		t.Errorf("the refusal still issued a code: %v", body)
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func TestADeviceFlowCannotRequestScopesTheClientIsNotRegisteredFor(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx,
		`UPDATE core.clients SET grant_types = grant_types || ARRAY['urn:ietf:params:oauth:grant-type:device_code'],
		 scopes = ARRAY['openid'] WHERE client_id = $1`, f.clientID); err != nil {
		t.Fatal(err)
	}

	post := func(scope string) (int, map[string]any) {
		form := url.Values{"client_id": {f.clientID}, "scope": {scope}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	status, body := post("openid admin")
	if status == http.StatusOK {
		t.Fatalf("a device authorization was issued for the scope `admin`, which "+
			"this client is not registered for; the verification page would then "+
			"invite a user to approve it: %v", body)
	}
	if body["error"] != "invalid_scope" {
		t.Errorf("error is %v, want invalid_scope: %v", body["error"], body)
	}
	// Nothing handed out — a refusal that still mints a user code leaves a code
	// somebody can be talked into approving.
	if body["user_code"] != nil || body["device_code"] != nil {
		t.Errorf("the refusal still issued a code: %v", body)
	}

	// A registered scope still works, or the check above would pass by refusing
	// everything.
	if status, body := post("openid"); status != http.StatusOK {
		t.Fatalf("a registered scope was refused: %d %v", status, body)
	}
}
