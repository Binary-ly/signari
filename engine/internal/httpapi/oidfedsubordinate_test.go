package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// This deployment as what others in a federation look up to (12.11). What is under test
// is the chain: a resolver that trusts this entity's keys alone, and everything else it
// learns from fetching.

const leafEntity = "https://leaf.example.test"

type anchorFixture struct {
	*tmFixture
	leafKey *ecdsa.PrivateKey
	// hints is what the leaf says of its superiors.
	hints []string
	// marks are the Trust Marks the leaf's configuration carries.
	marks []oidfed.TrustMarkEntry
	// elsewhere answers for another host, a second anchor, when set.
	elsewhere func(r *http.Request) (string, bool)
}

func newAnchorFixture(t *testing.T, change store.FederationChange) *anchorFixture {
	t.Helper()
	ctx := context.Background()
	f := newTrustMarkFixture(t)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM core.signing_keys WHERE instance_id = $1::uuid`, f.instanceID)
	})
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.root = root
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.EnableFederation(ctx, tx, root, f.instanceID, f.issuer, change); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if f.srv.fedKeys, err = keys.LoadSetFor(ctx, f.pool, f.instanceID, keys.PurposeFederation, root); err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &anchorFixture{tmFixture: f, leafKey: k, hints: []string{f.issuer}}
	// Every outbound call lands here: this engine for its own name, a leaf for the other.
	f.srv.outboundHTTP = func(time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			if body, ok := a.answerElsewhere(r); ok {
				rec.Header().Set("Content-Type", oidfed.MediaType)
				_, _ = rec.WriteString(body)
			} else if r.URL.Host == strings.TrimPrefix(leafEntity, "https://") {
				rec.Header().Set("Content-Type", oidfed.MediaType)
				_, _ = rec.WriteString(a.leafStatement(t))
			} else {
				f.srv.Routes().ServeHTTP(rec, r)
			}
			return rec.Result(), nil
		})}
	}
	return a
}

func (a *anchorFixture) answerElsewhere(r *http.Request) (string, bool) {
	if a.elsewhere == nil {
		return "", false
	}
	return a.elsewhere(r)
}

func (a *anchorFixture) leafJWKS(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: a.leafKey.Public(), KeyID: "leaf-1", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *anchorFixture) leafStatement(t *testing.T) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.leafKey},
		(&jose.SignerOptions{}).WithType(oidfed.Typ).WithHeader("kid", "leaf-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": leafEntity, "sub": leafEntity,
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"jwks": json.RawMessage(a.leafJWKS(t)), "authority_hints": a.hints,
		"metadata": map[string]any{"openid_relying_party": map[string]any{
			"client_name": "Leaf", "contacts": []string{"ops@leaf.example.test"}}}}
	if len(a.marks) > 0 {
		claims["trust_marks"] = a.marks
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a *anchorFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	a.srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func (a *anchorFixture) errorOf(t *testing.T, path string, status int) string {
	t.Helper()
	rec := a.get(t, path)
	if rec.Code != status {
		t.Errorf("%s answered %d, want %d: %s", path, rec.Code, status, rec.Body)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error
}

func (a *anchorFixture) federationEntity(t *testing.T) map[string]any {
	t.Helper()
	rec := a.get(t, oidfed.WellKnownPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("the Entity Configuration answered %d: %s", rec.Code, rec.Body)
	}
	metadata, _ := claimsOfJWT(t, rec.Body.String())["metadata"].(map[string]any)
	entity, _ := metadata["federation_entity"].(map[string]any)
	return entity
}

func (a *anchorFixture) speakFor(t *testing.T, sub store.Subordinate) {
	t.Helper()
	if err := store.SetSubordinate(context.Background(), a.pool, a.instanceID, sub); err != nil {
		t.Fatal(err)
	}
}

func TestAChainResolvesThroughThisDeployment(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	ctx := context.Background()
	if entity := a.federationEntity(t); entity["federation_fetch_endpoint"] != a.issuer+"/federation/fetch" ||
		entity["federation_list_endpoint"] != a.issuer+"/federation/list" {
		t.Fatalf("a Trust Anchor publishes %v", entity)
	}
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t),
		MetadataPolicy: []byte(`{"openid_relying_party":{"contacts":{"add":["fed@anchor.example.test"]}}}`)})

	// A resolver that was told only this entity's keys, as anybody in the federation is.
	jwks, err := a.srv.fedKeys.MarshalJWKS()
	if err != nil {
		t.Fatal(err)
	}
	resolver := oidfed.Resolver{Fetcher: &oidfed.Fetcher{HTTP: a.srv.outboundHTTP(time.Second)},
		Anchors: []oidfed.TrustAnchor{{EntityID: a.issuer, JWKS: jwks}}}
	result, chain, err := resolver.ResolveChain(ctx, leafEntity, time.Now())
	if err != nil {
		t.Fatalf("a chain through this entity did not resolve: %v", err)
	}
	if result.TrustAnchor != a.issuer || len(chain) != 2 || chain[1].Issuer != a.issuer || chain[1].Subject != leafEntity {
		t.Fatalf("resolved %+v in %d statements", result, len(chain))
	}

	// And the same from the resolve endpoint.
	rec := a.get(t, "/federation/resolve?sub="+url.QueryEscape(leafEntity)+"&trust_anchor="+url.QueryEscape(a.issuer))
	if rec.Code != http.StatusOK {
		t.Fatalf("resolving gave %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/resolve-response+jwt" {
		t.Errorf("served as %q", got)
	}
	signed := rec.Body.String()
	parsed, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if typ := parsed.Signatures[0].Protected.ExtraHeaders[jose.HeaderType]; typ != oidfed.ResolveResponseTyp {
		t.Errorf("§8.3.2 wants typ %s, and got %v", oidfed.ResolveResponseTyp, typ)
	}
	claims := claimsOfJWT(t, signed)
	if claims["iss"] != a.issuer || claims["sub"] != leafEntity {
		t.Errorf("about %v from %v", claims["sub"], claims["iss"])
	}
	if links, _ := claims["trust_chain"].([]any); len(links) != 3 {
		t.Errorf("§8.3.2: the trust_chain is %v", claims["trust_chain"])
	}
	metadata, _ := claims["metadata"].(map[string]any)
	party, _ := metadata["openid_relying_party"].(map[string]any)
	if party["client_name"] != "Leaf" || !strings.Contains(strings.Join(anyStrings(party["contacts"]), ","), "fed@anchor.example.test") {
		t.Errorf("the policy was not applied: %v", metadata)
	}

	// Asked for one Entity Type, that one.
	rec = a.get(t, "/federation/resolve?sub="+url.QueryEscape(leafEntity)+"&trust_anchor="+url.QueryEscape(a.issuer)+
		"&entity_type=federation_entity")
	if rec.Code != http.StatusOK {
		t.Fatalf("resolving one type gave %d: %s", rec.Code, rec.Body)
	}
	metadata, _ = claimsOfJWT(t, rec.Body.String())["metadata"].(map[string]any)
	if metadata["openid_relying_party"] != nil {
		t.Errorf("a type nobody asked for came back: %v", metadata)
	}
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

// The keys in a statement are the ones the operator was given, not the ones the subject shows
// at the moment of asking, which is the whole of what the statement is worth.
func TestAKeyTheStatementDoesNotNameBreaksTheChain(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t)})
	stolen, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.leafKey = stolen
	path := "/federation/resolve?sub=" + url.QueryEscape(leafEntity) + "&trust_anchor=" + url.QueryEscape(a.issuer)
	if e := a.errorOf(t, path, http.StatusBadRequest); e != "invalid_trust_chain" {
		t.Errorf("a subject with other keys answered %q", e)
	}
}

func TestStoppingSpeakingForAnEntityEndsItsChain(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t)})
	fetch := "/federation/fetch?sub=" + url.QueryEscape(leafEntity)
	if rec := a.get(t, fetch); rec.Code != http.StatusOK {
		t.Fatalf("fetching gave %d: %s", rec.Code, rec.Body)
	}
	if err := store.RemoveSubordinate(context.Background(), a.pool, a.instanceID, leafEntity); err != nil {
		t.Fatal(err)
	}
	if e := a.errorOf(t, fetch, http.StatusNotFound); e != "not_found" {
		t.Errorf("a removed subordinate answered %q", e)
	}
	path := "/federation/resolve?sub=" + url.QueryEscape(leafEntity) + "&trust_anchor=" + url.QueryEscape(a.issuer)
	if e := a.errorOf(t, path, http.StatusBadRequest); e != "invalid_trust_chain" {
		t.Errorf("resolving a removed subordinate answered %q", e)
	}
}

func TestAStatementSaysWhatIsKnownAboutItsSubject(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	two := 2
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t), MaxPathLength: &two, Intermediate: true})
	rec := a.get(t, "/federation/fetch?sub="+url.QueryEscape(leafEntity))
	if rec.Code != http.StatusOK {
		t.Fatalf("fetching gave %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != oidfed.MediaType {
		t.Errorf("§8.1.2 wants %s, and got %q", oidfed.MediaType, got)
	}
	claims := claimsOfJWT(t, rec.Body.String())
	if claims["iss"] != a.issuer || claims["sub"] != leafEntity {
		t.Errorf("about %v from %v", claims["sub"], claims["iss"])
	}
	if claims["source_endpoint"] != a.issuer+"/federation/fetch" {
		t.Errorf("source_endpoint is %v", claims["source_endpoint"])
	}
	constraints, _ := claims["constraints"].(map[string]any)
	if constraints["max_path_length"] != float64(2) {
		t.Errorf("constraints are %v", claims["constraints"])
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= time.Now().Unix() {
		t.Errorf("expires %v", claims["exp"])
	}

	// §8.1.2's two RECOMMENDED codes.
	if e := a.errorOf(t, "/federation/fetch?sub="+url.QueryEscape("https://nobody.example.test"), http.StatusNotFound); e != "not_found" {
		t.Errorf("nobody answered %q", e)
	}
	if e := a.errorOf(t, "/federation/fetch?sub="+url.QueryEscape(a.issuer), http.StatusBadRequest); e != "invalid_request" {
		t.Errorf("itself answered %q", e)
	}
	if e := a.errorOf(t, "/federation/fetch", http.StatusBadRequest); e != "invalid_request" {
		t.Errorf("no sub answered %q", e)
	}
}

func TestTheListIsWhoThisEntitySpeaksFor(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t)})
	a.speakFor(t, store.Subordinate{EntityID: "https://inter.example.test", JWKS: a.leafJWKS(t), Intermediate: true})
	listed := func(path string) []string {
		t.Helper()
		rec := a.get(t, path)
		var out []string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s gave %d %s", path, rec.Code, rec.Body)
		}
		return out
	}
	if got := listed("/federation/list"); strings.Join(got, " ") != "https://inter.example.test "+leafEntity {
		t.Errorf("listed %v", got)
	}
	if got := listed("/federation/list?intermediate=true"); strings.Join(got, " ") != "https://inter.example.test" {
		t.Errorf("intermediates are %v", got)
	}
	// §8.2.1: a filter it cannot apply is refused, or the list would look filtered and be wrong.
	if e := a.errorOf(t, "/federation/list?entity_type=openid_provider", http.StatusBadRequest); e != "unsupported_parameter" {
		t.Errorf("entity_type answered %q", e)
	}
	// The marks this entity issued it can filter by: a live one counts, a revoked one does not.
	const member = "https://anchor.example.test/marks/member"
	if got := listed("/federation/list?trust_marked=true"); len(got) != 0 {
		t.Errorf("with no marks issued, trust_marked listed %v", got)
	}
	a.issue(t, member, leafEntity, time.Hour)
	for path, want := range map[string]string{
		"/federation/list?trust_marked=true":                                            leafEntity,
		"/federation/list?trust_marked=false":                                           "https://inter.example.test " + leafEntity,
		"/federation/list?trust_mark_type=" + url.QueryEscape(member):                   leafEntity,
		"/federation/list?trust_mark_type=https%3A%2F%2Fother.test%2Fm":                 "",
		"/federation/list?trust_marked=true&intermediate=true":                          "",
		"/federation/list?trust_marked=true&trust_mark_type=" + url.QueryEscape(member): leafEntity,
	} {
		if got := strings.Join(listed(path), " "); got != want {
			t.Errorf("%s listed %q, want %q", path, got, want)
		}
	}
	if err := store.RevokeTrustMark(context.Background(), a.pool, a.instanceID, member, leafEntity, "a test"); err != nil {
		t.Fatal(err)
	}
	if got := listed("/federation/list?trust_marked=true"); len(got) != 0 {
		t.Errorf("a revoked mark still lists %v", got)
	}
}

// §5.1.1: Intermediates and Trust Anchors MUST publish a fetch endpoint and Leaf Entities
// MUST NOT, so an entity with a superior becomes an Intermediate by speaking for somebody.
func TestOnlyAnEntityThatSpeaksForSomebodyPublishesTheEndpoints(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{AuthorityHints: []string{"https://anchor.example.test"}})
	if entity := a.federationEntity(t); entity["federation_fetch_endpoint"] != nil {
		t.Errorf("a Leaf Entity publishes %v", entity)
	}
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t)})
	if entity := a.federationEntity(t); entity["federation_fetch_endpoint"] == nil {
		t.Errorf("an Intermediate publishes %v", entity)
	}
}

// signedStatement signs claims as an entity statement with key, as another entity would.
func signedStatement(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// §8.3.2: a resolve response carries the subject's Trust Marks this entity can stand
// behind, and lasts no longer than the first of them to expire; one signed in this
// entity's name by anybody else is left out.
func TestAResolveResponseCarriesOnlyVerifiedTrustMarks(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	a.speakFor(t, store.Subordinate{EntityID: leafEntity, JWKS: a.leafJWKS(t)})
	const member, forgedType = "https://anchor.example.test/marks/member", "https://anchor.example.test/marks/forged"
	// Issued as this entity issues one: signed with the Federation Entity Key it publishes.
	fedKey, err := a.srv.fedKeys.Active(keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	built := func(markType string, life time.Duration) *oidfed.TrustMark {
		t.Helper()
		mark, err := oidfed.BuildTrustMark(oidfed.TrustMarkParams{Issuer: a.issuer, Subject: leafEntity, Type: markType,
			Lifetime: life}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return mark
	}
	genuine, err := tokens.NewSigner(fedKey).SignJSON(built(member, 10*time.Minute), oidfed.TrustMarkTyp)
	if err != nil {
		t.Fatal(err)
	}
	// The same, in this entity's name, signed by the leaf.
	raw, _ := json.Marshal(built(forgedType, time.Hour))
	var markClaims map[string]any
	_ = json.Unmarshal(raw, &markClaims)
	forged := signedStatement(t, a.leafKey, "leaf-1", oidfed.TrustMarkTyp, markClaims)
	a.marks = []oidfed.TrustMarkEntry{{Type: member, JWT: genuine}, {Type: forgedType, JWT: forged}}

	rec := a.get(t, "/federation/resolve?sub="+url.QueryEscape(leafEntity)+"&trust_anchor="+url.QueryEscape(a.issuer))
	if rec.Code != http.StatusOK {
		t.Fatalf("resolving gave %d: %s", rec.Code, rec.Body)
	}
	claims := claimsOfJWT(t, rec.Body.String())
	marks, _ := claims["trust_marks"].([]any)
	if len(marks) != 1 || marks[0].(map[string]any)["trust_mark"] != genuine {
		t.Fatalf("the response carries %v", claims["trust_marks"])
	}
	if exp, _ := claims["exp"].(float64); int64(exp) > time.Now().Add(10*time.Minute+time.Second).Unix() {
		t.Errorf("the response outlives its trust mark: exp %v", claims["exp"])
	}
}

// A chain ending at a Trust Anchor the operator listed resolves, verified with the keys
// the operator gave; listed with other keys, it does not; not listed, it is refused.
func TestAChainEndingAtAListedAnchorResolves(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	ctx := context.Background()
	const other = "https://other-anchor.example.test"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keySet := func(k *ecdsa.PrivateKey) json.RawMessage {
		raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: k.Public(), KeyID: "other-1", Algorithm: "ES256", Use: "sig"}}})
		return raw
	}
	a.hints = []string{other}
	a.elsewhere = func(r *http.Request) (string, bool) {
		if r.URL.Host != strings.TrimPrefix(other, "https://") {
			return "", false
		}
		now := time.Now()
		switch {
		case r.URL.Path == "/.well-known/openid-federation":
			return signedStatement(t, key, "other-1", oidfed.Typ, map[string]any{"iss": other, "sub": other,
				"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(), "jwks": keySet(key),
				"metadata": map[string]any{"federation_entity": map[string]any{
					"federation_fetch_endpoint": other + "/fetch"}}}), true
		case r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == leafEntity:
			return signedStatement(t, key, "other-1", oidfed.Typ, map[string]any{"iss": other, "sub": leafEntity,
				"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
				"jwks": json.RawMessage(a.leafJWKS(t))}), true
		}
		return "", false
	}
	resolve := "/federation/resolve?sub=" + url.QueryEscape(leafEntity) + "&trust_anchor=" + url.QueryEscape(other)
	if e := a.errorOf(t, resolve, http.StatusNotFound); e != "invalid_trust_anchor" {
		t.Errorf("an anchor nobody listed answered %q", e)
	}

	var org string
	if err := a.pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1::uuid, $2, 'listed anchor') RETURNING id::text`, a.instanceID,
		"listed-"+strconv.FormatInt(time.Now().UnixNano(), 36)).Scan(&org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.pool.Exec(context.Background(), `DELETE FROM core.organizations WHERE id = $1::uuid`, org)
	})
	list := func(jwks json.RawMessage) {
		t.Helper()
		if err := store.SetFederationAnchor(ctx, a.pool, a.instanceID, store.FederationAnchor{EntityID: other, OrgID: org,
			JWKS: jwks}); err != nil {
			t.Fatal(err)
		}
	}

	list(keySet(key))
	rec := a.get(t, resolve)
	if rec.Code != http.StatusOK {
		t.Fatalf("a chain to a listed anchor gave %d: %s", rec.Code, rec.Body)
	}
	claims := claimsOfJWT(t, rec.Body.String())
	links, _ := claims["trust_chain"].([]any)
	if claims["iss"] != a.issuer || len(links) != 3 {
		t.Fatalf("resolved by %v through %d statements", claims["iss"], len(links))
	}
	if last := claimsOfJWT(t, links[2].(string)); last["sub"] != other {
		t.Errorf("the chain ends at %v", last["sub"])
	}

	// Listed with keys the anchor does not sign with: whoever answers there is not it.
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list(keySet(stranger))
	if e := a.errorOf(t, resolve, http.StatusBadRequest); e != "invalid_trust_chain" {
		t.Errorf("an anchor answering with other keys gave %q", e)
	}
}

func TestResolvingAnotherAnchorIsNotThisEntitysToSay(t *testing.T) {
	a := newAnchorFixture(t, store.FederationChange{})
	if e := a.errorOf(t, "/federation/resolve?sub=x&trust_anchor="+url.QueryEscape("https://elsewhere.example.test"),
		http.StatusNotFound); e != "invalid_trust_anchor" {
		t.Errorf("another anchor answered %q", e)
	}
	if e := a.errorOf(t, "/federation/resolve?sub="+url.QueryEscape(leafEntity), http.StatusBadRequest); e != "invalid_request" {
		t.Errorf("no anchor answered %q", e)
	}
}
