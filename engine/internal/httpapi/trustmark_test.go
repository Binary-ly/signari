package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/oidfed"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/tokens"
)

// The Trust Mark Issuer endpoints, §8.4 to §8.6, end to end against a database.
//
// The cases that matter here are the ones where an endpoint could answer a
// question it was not asked: a superseded mark reported active, a revoked mark
// still listed, an unknown mark answered with a signed statement about it.

type tmFixture struct {
	srv        *Server
	pool       *pgxpool.Pool
	instanceID string
	issuer     string
	fedKey     keys.Key
}

func newTrustMarkFixture(t *testing.T) *tmFixture {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set; skipping database-backed tests")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE signari_maintenance")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	protocolKey, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	activeProtocol, _ := keys.WithState(protocolKey, keys.StateActive)
	protocolSet, err := keys.NewSet(activeProtocol)
	if err != nil {
		t.Fatal(err)
	}

	f := &tmFixture{pool: pool}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.instances (issuer, display_name)
		VALUES ('https://tm-' || gen_random_uuid() || '.test', 'TM')
		RETURNING id::text, issuer`).Scan(&f.instanceID, &f.issuer); err != nil {
		t.Fatalf("fixture instance: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Dependency order, and errors reported rather than discarded. A cleanup
		// that silently fails leaves rows in a shared database and breaks an
		// unrelated test later, which is exactly how a whole afternoon goes.
		for _, q := range []string{
			`DELETE FROM core.federation_trust_marks_issued WHERE instance_id = $1::uuid`,
			`DELETE FROM core.federation_trust_marks_held WHERE instance_id = $1::uuid`,
			`DELETE FROM core.federation_config WHERE instance_id = $1::uuid`,
			`DELETE FROM core.instances WHERE id = $1::uuid`,
		} {
			if _, err := pool.Exec(c, q, f.instanceID); err != nil {
				t.Errorf("cleanup %q: %v", q, err)
			}
		}
	})

	srv, err := New(oidc.Config{
		Issuer: f.issuer, Keys: protocolSet, AllowInsecureIssuer: true,
	}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.instanceID = f.instanceID

	// The FEDERATION key set, distinct from the protocol one. §7 requires a
	// Trust Mark to be signed with a Federation Entity Key, and a fixture that
	// reused the protocol key would let a swap between them pass unnoticed --
	// which is the one mistake this separation exists to prevent.
	fk, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	activeFed, _ := keys.WithState(fk, keys.StateActive)
	fedSet, err := keys.NewSet(activeFed)
	if err != nil {
		t.Fatal(err)
	}
	srv.fedKeys = fedSet
	f.fedKey = activeFed
	f.srv = srv
	return f
}

// issue mints and records a Trust Mark, returning the compact serialisation.
func (f *tmFixture) issue(t *testing.T, markType, subject string, lifetime time.Duration) string {
	return f.issueAt(t, markType, subject, lifetime, time.Now())
}

// issueAt mints a mark as of some other moment.
//
// The only way to produce an already-expired mark through the real path:
// BuildTrustMark refuses a negative lifetime, correctly, so a test that wants a
// lapsed row has to move the clock rather than the duration. Doing it by writing
// the row directly would test the query against a document this code cannot
// actually mint.
func (f *tmFixture) issueAt(t *testing.T, markType, subject string,
	lifetime time.Duration, now time.Time) string {
	t.Helper()
	tm, err := oidfed.BuildTrustMark(oidfed.TrustMarkParams{
		Issuer: f.issuer, Subject: subject, Type: markType, Lifetime: lifetime,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tokens.NewSigner(f.fedKey).SignJSON(tm, oidfed.TrustMarkTyp)
	if err != nil {
		t.Fatal(err)
	}
	var exp time.Time
	if tm.Expiry != 0 {
		exp = time.Unix(tm.Expiry, 0)
	}
	if err := store.IssueTrustMark(context.Background(), f.pool, f.instanceID,
		store.IssuedTrustMark{Type: markType, Subject: subject, JWT: signed, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *tmFixture) status(t *testing.T, raw string) (int, string, []byte) {
	t.Helper()
	form := url.Values{}
	if raw != "" {
		form.Set("trust_mark", raw)
	}
	req := httptest.NewRequest(http.MethodPost, trustMarkStatusPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleTrustMarkStatus(rec, req)
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.Bytes()
}

func (f *tmFixture) list(t *testing.T, markType, sub string) (int, []string) {
	t.Helper()
	q := url.Values{}
	if markType != "" {
		q.Set("trust_mark_type", markType)
	}
	if sub != "" {
		q.Set("sub", sub)
	}
	req := httptest.NewRequest(http.MethodGet, trustMarkListPath+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.srv.handleTrustMarkList(rec, req)
	var out []string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *tmFixture) fetch(t *testing.T, markType, sub string) (int, string, string) {
	t.Helper()
	q := url.Values{}
	if markType != "" {
		q.Set("trust_mark_type", markType)
	}
	if sub != "" {
		q.Set("sub", sub)
	}
	req := httptest.NewRequest(http.MethodGet, trustMarkPath+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	f.srv.handleTrustMark(rec, req)
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.String()
}

// decodeStatus verifies the response is a signed status JWT and returns it.
func (f *tmFixture) decodeStatus(t *testing.T, body []byte) oidfed.StatusResponse {
	t.Helper()
	tok, err := jose.ParseSigned(string(body), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("the status response is not a signed JWT: %v\nbody: %s", err, body)
	}
	// §8.4.2: "It is signed with a Federation Entity Key."
	pub := f.fedKey.Signer().Public()
	payload, err := tok.Verify(pub)
	if err != nil {
		t.Fatalf("the status response did not verify against the federation key: %v", err)
	}
	if typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != oidfed.StatusResponseTyp {
		t.Errorf("typ = %q, want %q", typ, oidfed.StatusResponseTyp)
	}
	var sr oidfed.StatusResponse
	if err := json.Unmarshal(payload, &sr); err != nil {
		t.Fatal(err)
	}
	return sr
}

const tmType = "https://fed.example/profile/privacy-v2"

func TestTrustMarkStatusAnswersAboutTheExactDocument(t *testing.T) {
	f := newTrustMarkFixture(t)
	raw := f.issue(t, tmType, "https://rp.example", time.Hour)

	code, ct, body := f.status(t, raw)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body %s", code, body)
	}
	// §8.4.2's content type, which is what tells a caller this is a signed
	// object rather than the JSON earlier drafts returned.
	if ct != oidfed.StatusResponseMediaType {
		t.Errorf("Content-Type = %q, want %q", ct, oidfed.StatusResponseMediaType)
	}
	sr := f.decodeStatus(t, body)
	if sr.Status != oidfed.StatusActive {
		t.Errorf("status = %q, want active", sr.Status)
	}
	if sr.TrustMark != raw {
		t.Error("the response does not echo the Trust Mark it is about, so a " +
			"caller holding several cannot tell which one was answered")
	}
	if sr.Issuer != f.issuer {
		t.Errorf("iss = %q, want %q", sr.Issuer, f.issuer)
	}
}

// A superseded mark must not be reported active.
//
// This is the case the Final specification's request shape exists for. Asking by
// (type, subject) cannot distinguish the two documents: they share coordinates,
// and only one of them is the one in the caller's hand.
func TestASupersededTrustMarkIsNotReportedActive(t *testing.T) {
	f := newTrustMarkFixture(t)
	first := f.issue(t, tmType, "https://rp.example", time.Hour)
	second := f.issue(t, tmType, "https://rp.example", time.Hour)
	if first == second {
		t.Fatal("the two issuances produced identical bytes, so this test cannot " +
			"distinguish them")
	}

	code, _, body := f.status(t, first)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if got := f.decodeStatus(t, body).Status; got != oidfed.StatusRevoked {
		t.Errorf("the superseded mark reports %q; a holder of the OLD document "+
			"would keep using it", got)
	}

	code, _, body = f.status(t, second)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if got := f.decodeStatus(t, body).Status; got != oidfed.StatusActive {
		t.Errorf("the current mark reports %q, want active", got)
	}
}

// §8.4.2: an unknown Trust Mark gets 404, and specifically NOT a signed
// `invalid` -- which would be this entity minting a statement about bytes it has
// never seen, that the presenter could then wave around as proof we considered
// them.
func TestAnUnknownTrustMarkGets404AndNoSignedStatement(t *testing.T) {
	f := newTrustMarkFixture(t)
	stranger := newTrustMarkFixture(t)
	foreign := stranger.issue(t, tmType, "https://rp.example", time.Hour)

	code, ct, body := f.status(t, foreign)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", code, body)
	}
	if ct == oidfed.StatusResponseMediaType {
		t.Error("a signed status response was returned for a mark this entity " +
			"never issued")
	}
	if strings.Count(string(body), ".") >= 2 && !strings.HasPrefix(string(body), "{") {
		t.Errorf("the 404 body looks like a JWT: %s", body)
	}
}

func TestTrustMarkStatusRequiresItsParameter(t *testing.T) {
	f := newTrustMarkFixture(t)
	code, _, body := f.status(t, "")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	var e map[string]any
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("the error is not JSON: %s", body)
	}
	// §8.9 makes both members REQUIRED. A code alone tells a federation operator
	// that something is wrong and nothing about what.
	if e["error"] != "invalid_request" {
		t.Errorf("error = %v", e["error"])
	}
	if s, _ := e["error_description"].(string); s == "" {
		t.Error("error_description is missing, and section 8.9 makes it REQUIRED")
	}
}

// A revoked mark leaves the listing, and does so in SQL.
func TestTheListingExcludesRevokedAndExpiredMarks(t *testing.T) {
	f := newTrustMarkFixture(t)
	f.issue(t, tmType, "https://live.example", time.Hour)
	f.issue(t, tmType, "https://revoked.example", time.Hour)
	// Issued two hours ago with a one-hour life: the row exists and its status
	// column says `active`, so only the expiry filter can keep it out.
	f.issueAt(t, tmType, "https://stale.example", time.Hour,
		time.Now().Add(-2*time.Hour))

	if err := store.RevokeTrustMark(context.Background(), f.pool, f.instanceID,
		tmType, "https://revoked.example", "failed reassessment"); err != nil {
		t.Fatal(err)
	}

	code, got := f.list(t, tmType, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(got) != 1 || got[0] != "https://live.example" {
		t.Errorf("listing = %v, want only live.example; a withdrawn or lapsed "+
			"accreditation is being published as current", got)
	}
}

// §8.5.1's optional `sub` filter.
func TestTheListingHonoursTheSubjectFilter(t *testing.T) {
	f := newTrustMarkFixture(t)
	f.issue(t, tmType, "https://a.example", time.Hour)
	f.issue(t, tmType, "https://b.example", time.Hour)

	if _, got := f.list(t, tmType, ""); len(got) != 2 {
		t.Fatalf("unfiltered listing = %v, want two", got)
	}
	code, got := f.list(t, tmType, "https://b.example")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(got) != 1 || got[0] != "https://b.example" {
		t.Errorf("filtered listing = %v", got)
	}
}

// §8.5.2 returns an array. Nobody holding a mark is an answer, not a 404, and
// specifically not `null` -- a client decoding into an array type fails on
// `null`, so "nobody" would arrive as a parse error.
func TestAnEmptyListingIsAnArrayNotNull(t *testing.T) {
	f := newTrustMarkFixture(t)
	req := httptest.NewRequest(http.MethodGet,
		trustMarkListPath+"?trust_mark_type="+url.QueryEscape(tmType), nil)
	rec := httptest.NewRecorder()
	f.srv.handleTrustMarkList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Errorf("body = %q, want []", body)
	}
}

func TestTheTrustMarkEndpointServesAndRefuses(t *testing.T) {
	f := newTrustMarkFixture(t)
	raw := f.issue(t, tmType, "https://rp.example", time.Hour)

	t.Run("serves the mark", func(t *testing.T) {
		code, ct, body := f.fetch(t, tmType, "https://rp.example")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		if ct != oidfed.TrustMarkMediaType {
			t.Errorf("Content-Type = %q, want %q", ct, oidfed.TrustMarkMediaType)
		}
		if strings.TrimSpace(body) != raw {
			t.Error("the served mark is not byte-identical to the issued one; §8.4 " +
				"then cannot recognise what it hands out")
		}
	})

	t.Run("both parameters are required", func(t *testing.T) {
		if code, _, _ := f.fetch(t, tmType, ""); code != http.StatusBadRequest {
			t.Errorf("missing sub gave %d, want 400", code)
		}
		if code, _, _ := f.fetch(t, "", "https://rp.example"); code != http.StatusBadRequest {
			t.Errorf("missing trust_mark_type gave %d, want 400", code)
		}
	})

	// §8.6.2's 404, and the same 404 for revoked as for never-issued. Anybody
	// holding the mark can tell those apart at the status endpoint; telling a
	// stranger apart here would let them enumerate who we have accredited and
	// then withdrawn.
	t.Run("a revoked mark is indistinguishable from one never issued", func(t *testing.T) {
		if err := store.RevokeTrustMark(context.Background(), f.pool, f.instanceID,
			tmType, "https://rp.example", "withdrawn"); err != nil {
			t.Fatal(err)
		}
		revokedCode, _, revokedBody := f.fetch(t, tmType, "https://rp.example")
		unknownCode, _, unknownBody := f.fetch(t, tmType, "https://never-heard-of.example")
		if revokedCode != http.StatusNotFound || unknownCode != http.StatusNotFound {
			t.Fatalf("revoked = %d, unknown = %d; both should be 404",
				revokedCode, unknownCode)
		}
		if revokedBody != unknownBody {
			t.Errorf("the two 404s differ, which distinguishes an entity we once "+
				"accredited from one we never did:\n  revoked: %s\n  unknown: %s",
				revokedBody, unknownBody)
		}
	})
}

// The endpoints are advertised only once this entity has issued something.
func TestTheTrustMarkEndpointsAreAdvertisedOnlyByAnIssuer(t *testing.T) {
	f := newTrustMarkFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO core.federation_config (instance_id, authority_hints)
		VALUES ($1::uuid, ARRAY['https://anchor.example'])`, f.instanceID); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.FederationConfig(ctx, f.pool, f.instanceID)
	if err != nil {
		t.Fatal(err)
	}

	before := f.srv.federationMetadata(ctx, cfg)["federation_entity"].(map[string]any)
	for _, k := range []string{
		"federation_trust_mark_status_endpoint",
		"federation_trust_mark_list_endpoint",
		"federation_trust_mark_endpoint",
	} {
		if _, ok := before[k]; ok {
			t.Errorf("%s is advertised by an entity that has issued no Trust Mark", k)
		}
	}

	f.issue(t, tmType, "https://rp.example", time.Hour)

	after := f.srv.federationMetadata(ctx, cfg)["federation_entity"].(map[string]any)
	for _, k := range []string{
		"federation_trust_mark_status_endpoint",
		"federation_trust_mark_list_endpoint",
		"federation_trust_mark_endpoint",
	} {
		got, _ := after[k].(string)
		if got == "" {
			t.Errorf("%s is not advertised by an entity that has issued a Trust Mark", k)
			continue
		}
		if !strings.HasPrefix(got, f.issuer) {
			t.Errorf("%s = %q, which is not under this entity's issuer %q",
				k, got, f.issuer)
		}
	}

	// Revoking everything must NOT retract the advertisement: "was this
	// withdrawn" is exactly the question a status endpoint is for, and an issuer
	// that stopped answering after its last revocation would leave every holder
	// of a withdrawn mark unable to find out.
	if err := store.RevokeTrustMark(ctx, f.pool, f.instanceID, tmType,
		"https://rp.example", "withdrawn"); err != nil {
		t.Fatal(err)
	}
	still := f.srv.federationMetadata(ctx, cfg)["federation_entity"].(map[string]any)
	if _, ok := still["federation_trust_mark_status_endpoint"]; !ok {
		t.Error("the status endpoint stopped being advertised after the last mark " +
			"was revoked, which is when it matters most")
	}
}

// Expired held marks are excluded from what we publish, and the exclusion is in
// SQL rather than applied afterwards.
func TestExpiredHeldMarksAreNotPublished(t *testing.T) {
	f := newTrustMarkFixture(t)
	ctx := context.Background()
	other := newTrustMarkFixture(t)

	live := other.issue(t, tmType, f.issuer, time.Hour)
	stale := other.issue(t, "https://fed.example/profile/old", f.issuer, time.Hour)

	if err := store.AddHeldTrustMark(ctx, f.pool, f.instanceID, store.HeldTrustMark{
		Type: tmType, JWT: live, Issuer: other.issuer,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddHeldTrustMark(ctx, f.pool, f.instanceID, store.HeldTrustMark{
		Type: "https://fed.example/profile/old", JWT: stale, Issuer: other.issuer,
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	published, err := store.PublishableTrustMarks(ctx, f.pool, f.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != 1 || published[0].Type != tmType {
		t.Fatalf("published = %v; an expired accreditation is in our signed "+
			"Entity Configuration, where every reader is required to discard it",
			published)
	}
	// And it is still visible to an operator, so a lapse is noticed rather than
	// silently vanishing from the document.
	all, err := store.ListHeldTrustMarks(ctx, f.pool, f.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("the operator listing shows %d of 2 marks; a lapsed accreditation "+
			"disappeared instead of being reported", len(all))
	}
}

// The whole journey, from issuance to a reader's §7.3 verdict.
//
// Every other test in this file exercises one endpoint. This one is the loop a
// federation actually runs: an authority issues a mark, the subject publishes it
// in its Entity Configuration, and a relying party fetches that document and
// decides whether to believe it.
//
// It is here because the pieces can each be right while the loop is broken --
// the mark stored with a different serialisation than the one published, the
// wrong key set used for one of the two signatures, the outer and inner type
// identifiers assembled from different sources. None of those show up in a test
// that stops at one endpoint.
func TestATrustMarkSurvivesTheRoundTripFromIssuerToReader(t *testing.T) {
	authority := newTrustMarkFixture(t)
	subject := newTrustMarkFixture(t)
	ctx := context.Background()

	// 1. The authority accredits the subject.
	mark := authority.issue(t, tmType, subject.issuer, time.Hour)

	// 2. The subject publishes it.
	if _, err := subject.pool.Exec(ctx, `
		INSERT INTO core.federation_config (instance_id, authority_hints)
		VALUES ($1::uuid, ARRAY['https://anchor.example'])`, subject.instanceID); err != nil {
		t.Fatal(err)
	}
	if err := store.AddHeldTrustMark(ctx, subject.pool, subject.instanceID,
		store.HeldTrustMark{
			Type: tmType, JWT: mark, Issuer: authority.issuer,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	subject.srv.handleEntityConfiguration(rec,
		httptest.NewRequest(http.MethodGet, oidfed.WellKnownPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the entity configuration returned %d: %s", rec.Code, rec.Body)
	}

	// 3. A reader parses the configuration. Deliberately from the wire bytes
	// rather than from the struct that produced them: a claim that is correct
	// in Go and wrong after marshalling is exactly the kind of fault this test
	// is for.
	tok, err := jose.ParseSigned(rec.Body.String(), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Subject    string                  `json:"sub"`
		TrustMarks []oidfed.TrustMarkEntry `json:"trust_marks"`
	}
	if err := json.Unmarshal(tok.UnsafePayloadWithoutVerification(), &conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.TrustMarks) != 1 {
		t.Fatalf("the published configuration carries %d trust marks, want 1",
			len(conf.TrustMarks))
	}

	// §3.1.2's syntactic rule, which a reader applies before any trust decision.
	if err := oidfed.ValidateTrustMarksClaim(conf.TrustMarks); err != nil {
		t.Fatalf("the published trust_marks claim is not syntactically valid: %v", err)
	}

	// 4. The reader has already established trust in the authority (§10) and so
	// holds its federation keys. Built here from the fixture's key rather than
	// read from the mark, which is the whole point of §7.3's ordering.
	authorityJWKS, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: authority.fedKey.Signer().Public(), KeyID: authority.fedKey.KID(),
		Algorithm: "ES256", Use: "sig",
	}}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := oidfed.ValidateTrustMark(conf.TrustMarks[0].JWT, oidfed.TrustMarkOptions{
		ContainingEntity: conf.Subject,
		IssuerJWKS:       authorityJWKS,
	})
	if err != nil {
		t.Fatalf("a mark this server issued and published does not survive its own "+
			"section 7.3 validation: %v", err)
	}
	if got.Issuer != authority.issuer || got.Subject != subject.issuer {
		t.Errorf("iss/sub = %q/%q, want %q/%q",
			got.Issuer, got.Subject, authority.issuer, subject.issuer)
	}

	// 5. And the reader can re-check with the issuer, on the exact bytes it read
	// out of the published document -- which only works if issuance, publication
	// and the status endpoint all agree about the serialisation.
	code, _, body := authority.status(t, conf.TrustMarks[0].JWT)
	if code != http.StatusOK {
		t.Fatalf("the issuer does not recognise the mark as published: %d %s", code, body)
	}
	if s := authority.decodeStatus(t, body).Status; s != oidfed.StatusActive {
		t.Errorf("status = %q, want active", s)
	}
}
