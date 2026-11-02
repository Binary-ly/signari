package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/clientauth"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
)

// Automatic Registration, from a stranger's first request. The federation is a real one
// on one TLS server, an anchor and a relying party, and all that is ever put on the
// engine's side is the anchor, on the list.

type federatedRP struct {
	*signInFixture
	ts                              *httptest.Server
	id, anchorID, issuerID          string
	entityKey, anchorKey, issuerKey *ecdsa.PrivateKey
	protocolKey                     *ecdsa.PrivateKey
	instanceID                      string
	marks                           []oidfed.TrustMarkEntry
	allowedIssuers                  map[string][]string
	anchorForged                    bool
	fetched                         atomic.Int64
	jtis                            int
}

func publicJWKS(t *testing.T, key *ecdsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signStatement(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newFederatedRP(t *testing.T) *federatedRP {
	t.Helper()
	f := newSignInFixture(t)
	rp := &federatedRP{signInFixture: f}
	for _, key := range []**ecdsa.PrivateKey{&rp.entityKey, &rp.anchorKey, &rp.issuerKey, &rp.protocolKey} {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		*key = generated
	}
	mux := http.NewServeMux()
	rp.ts = httptest.NewTLSServer(mux)
	t.Cleanup(rp.ts.Close)
	rp.id, rp.anchorID, rp.issuerID = rp.ts.URL+"/rp", rp.ts.URL+"/anchor", rp.ts.URL+"/issuer"

	statement := func(key *ecdsa.PrivateKey, kid string, claims map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			rp.fetched.Add(1)
			claims["iat"], claims["exp"] = time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix()
			w.Header().Set("Content-Type", oidfed.MediaType)
			_, _ = w.Write([]byte(signStatement(t, key, kid, oidfed.Typ, claims)))
		}
	}
	mux.HandleFunc("/anchor"+oidfed.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]any{"iss": rp.anchorID, "sub": rp.anchorID, "jwks": publicJWKS(t, rp.anchorKey, "anchor"),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": rp.anchorID + "/fetch"}}}
		if rp.allowedIssuers != nil {
			claims["trust_mark_issuers"] = rp.allowedIssuers
		}
		key := rp.anchorKey
		if rp.anchorForged {
			key = rp.entityKey
		}
		statement(key, "anchor", claims)(w, r)
	})
	mux.HandleFunc("/anchor/fetch", func(w http.ResponseWriter, r *http.Request) {
		sub, keys := r.URL.Query().Get("sub"), publicJWKS(t, rp.entityKey, "rp-entity")
		if sub == rp.issuerID {
			keys = publicJWKS(t, rp.issuerKey, "issuer")
		}
		statement(rp.anchorKey, "anchor", map[string]any{"iss": rp.anchorID, "sub": sub, "jwks": keys})(w, r)
	})
	mux.HandleFunc("/issuer"+oidfed.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		statement(rp.issuerKey, "issuer", map[string]any{"iss": rp.issuerID, "sub": rp.issuerID,
			"jwks": publicJWKS(t, rp.issuerKey, "issuer"), "authority_hints": []string{rp.anchorID}})(w, r)
	})
	mux.HandleFunc("/rp"+oidfed.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		statement(rp.entityKey, "rp-entity", map[string]any{
			"iss": rp.id, "sub": rp.id, "jwks": publicJWKS(t, rp.entityKey, "rp-entity"),
			"authority_hints": []string{rp.anchorID}, "trust_marks": rp.marks,
			"metadata": map[string]any{"openid_relying_party": map[string]any{
				"client_name": "A federated application", "redirect_uris": []string{"https://rp.test/federated"},
				"scope": "openid", "response_types": []string{"code"}, "jwks": publicJWKS(t, rp.protocolKey, "rp-protocol"),
			}},
		})(w, r)
	})

	f.srv.fetchFederation = func() *oidfed.Fetcher {
		return &oidfed.Fetcher{HTTP: rp.ts.Client(), AllowLoopbackForTesting: true}
	}
	ctx := context.Background()
	if err := f.pool.QueryRow(ctx, `SELECT instance_id::text FROM core.organizations WHERE id = $1::uuid`,
		f.orgID).Scan(&rp.instanceID); err != nil {
		t.Fatal(err)
	}
	f.srv.SetInstance(rp.instanceID)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.pool.Exec(c, `DELETE FROM core.clients WHERE client_id = $1`, rp.id)
		_, _ = f.pool.Exec(c, `DELETE FROM core.federation_trust_anchors WHERE entity_id = $1`, rp.anchorID)
	})
	return rp
}

func (rp *federatedRP) trustAnchor(t *testing.T, marks ...string) {
	t.Helper()
	if err := store.SetFederationAnchor(context.Background(), rp.pool, rp.instanceID, store.FederationAnchor{
		EntityID: rp.anchorID, OrgID: rp.orgID, JWKS: publicJWKS(t, rp.anchorKey, "anchor"), TrustMarks: marks}); err != nil {
		t.Fatal(err)
	}
}

// request is what the relying party would send, signed by key.
func (rp *federatedRP) request(t *testing.T, key *ecdsa.PrivateKey, change map[string]any) string {
	t.Helper()
	rp.jtis++
	claims := map[string]any{"iss": rp.id, "aud": rp.srv.cfg.Issuer, "client_id": rp.id,
		"jti": fmt.Sprintf("%d-%d", time.Now().UnixNano(), rp.jtis), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"response_type": "code", "scope": "openid", "redirect_uri": "https://rp.test/federated", "state": "fed-state",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"}
	for name, value := range change {
		claims[name] = value
	}
	return signRequest(t, key, jose.ES256, "rp-protocol", claims)
}

func (rp *federatedRP) authorize(t *testing.T, cookie, object string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+url.Values{"client_id": {rp.id}, "request": {object}}.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	rp.srv.handleAuthorize(rec, req)
	return rec
}

func (rp *federatedRP) registered(t *testing.T) bool {
	t.Helper()
	var there bool
	if err := rp.pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM core.clients WHERE client_id = $1)`,
		rp.id).Scan(&there); err != nil {
		t.Fatal(err)
	}
	return there
}

// §12.1, all the way: nothing registered, a first request, a person signing in, and a
// code redeemed with the keys the chain published, which is the only credential it has.
func TestARelyingPartyAFederationVouchesForSignsSomebodyIn(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	ctx := context.Background()
	cookie := rp.signInAndReturnCookie(t)

	first := rp.authorize(t, cookie, rp.request(t, rp.protocolKey, nil))
	if !rp.registered(t) {
		t.Fatalf("it was not admitted: %d %.300s", first.Code, first.Body)
	}
	var org, name, kind, method, anchor string
	var hasSecret, signedOnly bool
	var expires time.Time
	if err := rp.pool.QueryRow(ctx, `SELECT org_id::text, display_name, client_type, token_endpoint_auth_method,
		federation_anchor, client_secret_hash IS NOT NULL, require_signed_request_object, federation_expires_at
		FROM core.clients WHERE client_id = $1`, rp.id).Scan(&org, &name, &kind, &method, &anchor, &hasSecret, &signedOnly, &expires); err != nil {
		t.Fatal(err)
	}
	if org != rp.orgID || name != "A federated application" || kind != "confidential" || method != "private_key_jwt" ||
		anchor != rp.anchorID || hasSecret || !signedOnly {
		t.Errorf("registered as org %s %q %s %s under %s, secret %v, signed %v", org, name, kind, method, anchor, hasSecret, signedOnly)
	}
	if time.Until(expires) <= 0 || time.Until(expires) > 2*time.Hour {
		t.Errorf("it expires in %v, want what the chain does", time.Until(expires))
	}

	// §12.1.1.1: redirect URIs come from the metadata, and a request naming another is
	// refused like any other client's.
	if _, err := rp.pool.Exec(ctx, `UPDATE core.clients SET first_party = true WHERE client_id = $1`, rp.id); err != nil {
		t.Fatal(err)
	}
	if off := rp.authorize(t, cookie, rp.request(t, rp.protocolKey, map[string]any{"redirect_uri": "https://evil.test/cb"})); strings.Contains(off.Header().Get("Location"), "evil.test") {
		t.Errorf("a redirect the metadata does not name was used: %q", off.Header().Get("Location"))
	}

	arrived := rp.authorize(t, cookie, rp.request(t, rp.protocolKey, nil))
	loc, err := url.Parse(arrived.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), "https://rp.test/federated") || loc.Query().Get("code") == "" {
		t.Fatalf("no code came back: %d %q: %.300s", arrived.Code, arrived.Header().Get("Location"), arrived.Body)
	}

	assertion := signStatement(t, rp.protocolKey, "rp-protocol", "JWT", map[string]any{"iss": rp.id, "sub": rp.id,
		"aud": rp.srv.cfg.Issuer, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "assert-1"})
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://rp.test/federated"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"client_assertion_type": {clientauth.AssertionType}, "client_assertion": {assertion}}
	req := httptest.NewRequest(http.MethodPost, oidc.PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	rp.srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "id_token") {
		t.Errorf("redeeming answered %d %.300s", rec.Code, rec.Body)
	}
}

// With nothing on the list nobody is admitted, and the server goes nowhere to find out.
func TestAnEmptyAnchorListMeansNobody(t *testing.T) {
	rp := newFederatedRP(t)
	rec := rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if rp.registered(t) {
		t.Error("a client was admitted with no anchors")
	}
	if n := rp.fetched.Load(); n != 0 {
		t.Errorf("%d fetches on a stranger's say-so, with nothing to check them against", n)
	}
	if rec.Header().Get("Location") != "" {
		t.Errorf("an unknown client was redirected to %q", rec.Header().Get("Location"))
	}
}

func TestAnAnchorNobodyListedVouchesForNobody(t *testing.T) {
	rp := newFederatedRP(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetFederationAnchor(context.Background(), rp.pool, rp.instanceID, store.FederationAnchor{
		EntityID: rp.anchorID, OrgID: rp.orgID, JWKS: publicJWKS(t, other, "impostor")}); err != nil {
		t.Fatal(err)
	}
	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if rp.registered(t) {
		t.Error("a chain ending at an anchor signed by other keys than the ones listed was believed")
	}
}

// A chain says who an entity is. Anybody can read that, so the request has to prove it:
// §12.1.1: "Attempted authentication requests that do not do so MUST be rejected."
func TestAVouchedForNameIsNotEnough(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec := rp.authorize(t, "", rp.request(t, stranger, nil))
	if rp.registered(t) {
		t.Error("a request signed by somebody else registered the client it named")
	}
	// §12.1.3: "it MUST treat the redirection URI as invalid".
	if rec.Header().Get("Location") != "" {
		t.Errorf("it redirected to %q", rec.Header().Get("Location"))
	}
	rp.authorize(t, "", rp.request(t, rp.entityKey, nil))
	if rp.registered(t) {
		t.Error("the federation key signed a protocol request, which §3.1.1 keeps apart")
	}
	for name, change := range map[string]map[string]any{
		"a sub":       {"sub": rp.id},
		"another aud": {"aud": []string{rp.srv.cfg.Issuer, "https://other.test"}},
		"no jti":      {"jti": ""},
	} {
		rp.authorize(t, "", rp.request(t, rp.protocolKey, change))
		if rp.registered(t) {
			t.Errorf("a request with %s was accepted", name)
		}
	}
}

// §12.1.1.1: "A Request Object MUST only be used once".
func TestARequestObjectFromAFederatedClientWorksOnce(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	object := rp.request(t, rp.protocolKey, nil)
	rp.authorize(t, "", object)
	if !rp.registered(t) {
		t.Fatal("not admitted")
	}
	// Shown and not sent: what names the redirect URI is the object that was refused.
	again := rp.authorize(t, "", object)
	if again.Code != http.StatusBadRequest || again.Header().Get("Location") != "" {
		t.Errorf("a request object sent twice answered %d %q: %.200s", again.Code, again.Header().Get("Location"), again.Body)
	}
}

func TestAnAnchorCanAskForATrustMark(t *testing.T) {
	rp := newFederatedRP(t)
	const accredited = "https://marks.test/accredited"
	rp.trustAnchor(t, accredited)

	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if rp.registered(t) {
		t.Fatal("a relying party with no mark was admitted to an anchor that asks for one")
	}

	mark := func(key *ecdsa.PrivateKey, kid, issuer, subject string) oidfed.TrustMarkEntry {
		return oidfed.TrustMarkEntry{Type: accredited, JWT: signStatement(t, key, kid, oidfed.TrustMarkTyp, map[string]any{
			"iss": issuer, "sub": subject, "trust_mark_type": accredited, "iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix()})}
	}
	refused := func(why string, entry oidfed.TrustMarkEntry) {
		t.Helper()
		rp.marks = []oidfed.TrustMarkEntry{entry}
		rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
		if rp.registered(t) {
			t.Fatal(why)
		}
	}
	refused("a mark issued to somebody else counted", mark(rp.anchorKey, "anchor", rp.anchorID, "https://somebody-else.test"))
	refused("a mark the anchor did not sign counted", mark(rp.entityKey, "anchor", rp.anchorID, rp.id))
	refused("a mark from an issuer nothing vouches for counted", mark(rp.entityKey, "stranger", "https://stranger.test", rp.id))

	// An issuer the anchor does not list for the type counts for nothing, however good.
	rp.allowedIssuers = map[string][]string{accredited: {rp.anchorID}}
	refused("an issuer the anchor rules out counted", mark(rp.issuerKey, "issuer", rp.issuerID, rp.id))
	rp.allowedIssuers = nil

	// What an anchor says of marks is believed only over the keys an operator listed:
	// whoever answers at its address could otherwise lift its rules.
	rp.anchorForged = true
	refused("an anchor's configuration nobody could verify was believed", mark(rp.anchorKey, "anchor", rp.anchorID, rp.id))
	rp.anchorForged = false

	admitted := func(why string, entry oidfed.TrustMarkEntry) {
		t.Helper()
		rp.marks = []oidfed.TrustMarkEntry{entry}
		rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
		if !rp.registered(t) {
			t.Fatal(why)
		}
		if _, err := rp.pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, rp.id); err != nil {
			t.Fatal(err)
		}
	}
	admitted("a mark from the anchor itself was not enough", mark(rp.anchorKey, "anchor", rp.anchorID, rp.id))
	admitted("a mark from an issuer under the anchor was not enough", mark(rp.issuerKey, "issuer", rp.issuerID, rp.id))
}

// What a chain said stops holding when the chain does, and is asked again.
func TestARegistrationIsLookedAtAgainWhenItExpires(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	ctx := context.Background()
	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if !rp.registered(t) {
		t.Fatal("not admitted")
	}
	expire := func() {
		t.Helper()
		if _, err := rp.pool.Exec(ctx, `UPDATE core.clients SET federation_expires_at = now() - interval '1 minute'
			WHERE client_id = $1`, rp.id); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	var left time.Duration
	if err := rp.pool.QueryRow(ctx, `SELECT extract(epoch FROM federation_expires_at - now())::bigint * interval '1 second'
		FROM core.clients WHERE client_id = $1`, rp.id).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left <= 0 {
		t.Errorf("an expired registration was not renewed: %v", left)
	}

	// And if the chain no longer stands, the client does not either, and is not sent to.
	expire()
	rp.ts.Close()
	rec := rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("a registration nothing vouches for answered %d %q: %.200s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

// A client somebody here made is theirs, whatever a federation says about the same name.
func TestAChainDoesNotTakeOverAClient(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	ctx := context.Background()
	if _, err := rp.pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type)
		VALUES ($1, $2::uuid, 'Made here', 'public')`, rp.id, rp.orgID); err != nil {
		t.Fatal(err)
	}
	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	var name string
	if err := rp.pool.QueryRow(ctx, `SELECT display_name FROM core.clients WHERE client_id = $1`, rp.id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Made here" {
		t.Errorf("a client made here became %q", name)
	}
	tx, err := rp.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := store.RegisterFederatedClient(ctx, tx, store.FederatedClient{ClientID: rp.id, OrgID: rp.orgID, Name: "Taken",
		Anchor: rp.anchorID, Scopes: []string{"openid"}, JWKS: publicJWKS(t, rp.protocolKey, "x"), Expiry: time.Now().Add(time.Hour)}); err == nil {
		t.Error("the writer overwrote a client somebody made")
	}
}

// configuration is the Entity Configuration an RP sends to register, tailored to this OP.
func (rp *federatedRP) configuration(t *testing.T, key *ecdsa.PrivateKey, kid string, change map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": rp.id, "sub": rp.id, "aud": rp.srv.cfg.Issuer, "iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(), "jwks": publicJWKS(t, key, kid), "authority_hints": []string{rp.anchorID},
		"metadata": map[string]any{"openid_relying_party": map[string]any{
			"client_name": "Tailored for this OP", "redirect_uris": []string{"https://rp.test/tailored"},
			"scope": "openid", "jwks": publicJWKS(t, rp.protocolKey, "rp-protocol"),
		}}}
	for name, value := range change {
		claims[name] = value
	}
	return signStatement(t, key, kid, oidfed.Typ, claims)
}

func (rp *federatedRP) register(t *testing.T, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, federationRegisterPath, strings.NewReader(body))
	req.RemoteAddr = freshAddress() + ":443"
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	rp.srv.Routes().ServeHTTP(rec, req)
	return rec
}

// federate gives the instance its federation keys, as `signari federation enable` does.
func (rp *federatedRP) federate(t *testing.T) {
	t.Helper()
	generated, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(generated, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	rp.srv.SetFederationKeys(set)
}

// §12.2, by both shapes of request, and what comes back is what the RP has to rely on.
func TestARelyingPartyRegistersExplicitly(t *testing.T) {
	rp := newFederatedRP(t)
	rp.federate(t)
	rp.trustAnchor(t)
	ctx := context.Background()

	chain, err := json.Marshal([]string{rp.configuration(t, rp.entityKey, "rp-entity", nil)})
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string][2]string{
		"a configuration": {"application/entity-statement+jwt", rp.configuration(t, rp.entityKey, "rp-entity", nil)},
		"a trust chain":   {"application/trust-chain+json", string(chain)},
	} {
		rec := rp.register(t, request[0], request[1])
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != registrationResponseType {
			t.Fatalf("%s answered %d %q: %.300s", name, rec.Code, rec.Header().Get("Content-Type"), rec.Body)
		}
		token, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		// §12.2.3: "MUST sign ... with a current Federation Entity Key".
		key, found := rp.srv.fedKeys.ByKID(token.Signatures[0].Header.KeyID)
		if !found {
			t.Fatalf("%s was signed with a key that is not a federation key", name)
		}
		payload, err := token.Verify(key.Signer().Public())
		if err != nil {
			t.Fatal(err)
		}
		if typ := token.Signatures[0].Protected.ExtraHeaders[jose.HeaderType]; typ != "explicit-registration-response+jwt" {
			t.Errorf("typ is %v", typ)
		}
		var claims struct {
			Issuer, Subject, Audience string
			Anchor                    string   `json:"trust_anchor"`
			Hints                     []string `json:"authority_hints"`
			Expiry                    int64    `json:"exp"`
			JWKS                      json.RawMessage
			Metadata                  map[string]map[string]any
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		var named map[string]any
		if err := json.Unmarshal(payload, &named); err != nil {
			t.Fatal(err)
		}
		if named["iss"] != rp.srv.cfg.Issuer || named["sub"] != rp.id || named["aud"] != rp.id {
			t.Errorf("%s: iss %v sub %v aud %v", name, named["iss"], named["sub"], named["aud"])
		}
		if claims.Anchor != rp.anchorID || len(claims.Hints) != 1 || claims.Hints[0] != rp.anchorID {
			t.Errorf("%s: anchor %q hints %q", name, claims.Anchor, claims.Hints)
		}
		if got := claims.Metadata["openid_relying_party"]["client_id"]; got != rp.id {
			t.Errorf("%s: client_id is %v", name, got)
		}
		// §12.3: "MUST NOT exceed the lifetime of the Trust Chain".
		if left := time.Until(time.Unix(claims.Expiry, 0)); left <= 0 || left > time.Hour {
			t.Errorf("%s: it lasts %v", name, left)
		}
		if !strings.Contains(string(claims.JWKS), "rp-entity") {
			t.Errorf("%s: jwks is not the RP's: %s", name, claims.JWKS)
		}
	}

	// What it sent is what counts, tailored as §12.2.2 says it may be.
	var title string
	var signedOnly, secret bool
	if err := rp.pool.QueryRow(ctx, `SELECT display_name, require_signed_request_object, client_secret_hash IS NOT NULL
		FROM core.clients WHERE client_id = $1`, rp.id).Scan(&title, &signedOnly, &secret); err != nil {
		t.Fatal(err)
	}
	if title != "Tailored for this OP" || signedOnly || secret {
		t.Errorf("registered as %q, signed requests %v, secret %v", title, signedOnly, secret)
	}
	var redirect string
	if err := rp.pool.QueryRow(ctx, `SELECT redirect_uri FROM core.client_redirect_uris WHERE client_id = $1`,
		rp.id).Scan(&redirect); err != nil || redirect != "https://rp.test/tailored" {
		t.Errorf("redirect is %q (%v)", redirect, err)
	}
}

// Anybody can sign an Entity Configuration that names an RP. What makes it the RP's is
// that the keys are the ones its superior attests to.
func TestAnExplicitRegistrationHasToBeTheRPs(t *testing.T) {
	rp := newFederatedRP(t)
	rp.federate(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const statement = "application/entity-statement+jwt"
	good := rp.configuration(t, rp.entityKey, "rp-entity", nil)

	if rec := rp.register(t, statement, good); rec.Code != http.StatusNotFound || rp.registered(t) {
		t.Errorf("with nothing on the list it answered %d", rec.Code)
	}
	rp.trustAnchor(t)
	for name, tc := range map[string]struct {
		contentType, body string
		code              int
	}{
		"self-signed by a stranger": {statement, rp.configuration(t, stranger, "rp-entity", nil), http.StatusBadRequest},
		"addressed to somebody else": {statement, rp.configuration(t, rp.entityKey, "rp-entity",
			map[string]any{"aud": "https://other.test"}), http.StatusBadRequest},
		"addressed to nobody": {statement, signStatement(t, rp.entityKey, "rp-entity", oidfed.Typ, map[string]any{
			"iss": rp.id, "sub": rp.id, "exp": time.Now().Add(time.Hour).Unix()}), http.StatusBadRequest},
		"about somebody else": {statement, rp.configuration(t, rp.entityKey, "rp-entity",
			map[string]any{"sub": "https://other.test"}), http.StatusBadRequest},
		"sent as something else": {"application/json", good, http.StatusBadRequest},
		"an empty chain":         {"application/trust-chain+json", "[]", http.StatusBadRequest},
		"not even a statement":   {statement, "nonsense", http.StatusBadRequest},
	} {
		if rec := rp.register(t, tc.contentType, tc.body); rec.Code != tc.code {
			t.Errorf("%s answered %d, want %d: %.200s", name, rec.Code, tc.code, rec.Body)
		}
		if rp.registered(t) {
			t.Fatalf("%s registered a client", name)
		}
	}
}

// The rules Automatic Registration has, because they are the same code.
func TestAnExplicitRegistrationIsHeldToWhatTheAnchorAsks(t *testing.T) {
	rp := newFederatedRP(t)
	rp.federate(t)
	rp.trustAnchor(t, "https://marks.test/accredited")
	if rec := rp.register(t, "application/entity-statement+jwt", rp.configuration(t, rp.entityKey, "rp-entity", nil)); rec.Code != http.StatusBadRequest || rp.registered(t) {
		t.Errorf("no mark answered %d", rec.Code)
	}
	ctx := context.Background()
	rp.trustAnchor(t)
	if _, err := rp.pool.Exec(ctx, `INSERT INTO core.clients (client_id, org_id, display_name, client_type)
		VALUES ($1, $2::uuid, 'Made here', 'public')`, rp.id, rp.orgID); err != nil {
		t.Fatal(err)
	}
	if rec := rp.register(t, "application/entity-statement+jwt", rp.configuration(t, rp.entityKey, "rp-entity", nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("registering over a client made here answered %d", rec.Code)
	}
}

// §12.1 and §12.2: "MUST include" the keyword, once it means something.
func TestRegistrationIsAdvertisedOnceAnAnchorIsListed(t *testing.T) {
	rp := newFederatedRP(t)
	rp.federate(t)
	read := func() map[string]any {
		t.Helper()
		op, _ := rp.srv.federationMetadata(context.Background(), &store.FederationSettings{})["openid_provider"].(map[string]any)
		return op
	}
	if got := read()["client_registration_types_supported"]; got != nil {
		t.Errorf("with no anchors it offers %v", got)
	}
	rp.trustAnchor(t)
	op := read()
	if got, _ := op["client_registration_types_supported"].([]string); len(got) != 2 {
		t.Errorf("client_registration_types_supported is %v", op["client_registration_types_supported"])
	}
	if op["federation_registration_endpoint"] != strings.TrimRight(rp.srv.cfg.Issuer, "/")+federationRegisterPath {
		t.Errorf("federation_registration_endpoint is %v", op["federation_registration_endpoint"])
	}
}

// Taking an anchor off the list takes back what it admitted.
func TestRemovingAnAnchorRemovesWhatItAdmitted(t *testing.T) {
	rp := newFederatedRP(t)
	rp.trustAnchor(t)
	ctx := context.Background()
	rp.authorize(t, "", rp.request(t, rp.protocolKey, nil))
	if !rp.registered(t) {
		t.Fatal("not admitted")
	}
	remove := func() (int64, error) {
		t.Helper()
		tx, err := rp.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		n, err := store.RemoveFederationAnchor(ctx, tx, rp.instanceID, rp.anchorID)
		if err == nil {
			err = tx.Commit(ctx)
		}
		return n, err
	}
	if n, err := remove(); err != nil || n != 1 {
		t.Fatalf("removing took %d clients (%v)", n, err)
	}
	if rp.registered(t) {
		t.Error("a client outlived the anchor that admitted it")
	}
	if _, err := remove(); !errors.Is(err, store.ErrFederationAnchorUnknown) {
		t.Errorf("removing it again answered %v", err)
	}
}
