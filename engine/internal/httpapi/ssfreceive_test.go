package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ssf"
)

// The whole inbound path, against a real database: a transmitter signs, we
// verify, resolve the subject to one of our users, and their sessions end.
//
// The endpoint is unauthenticated by design -- the signature is the credential
// -- so what this proves is that a signed event from a configured source does
// what it says, and that nothing else does anything at all.

func ssfTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// txServer is a transmitter serving its JWKS over TLS.
type txServer struct {
	key *ecdsa.PrivateKey
	kid string
	srv *httptest.Server
}

func newTXServer(t *testing.T) *txServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := &txServer{key: key, kid: "tx-e2e"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: key.Public(), KeyID: x.kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
	x.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(x.srv.Close)
	return x
}

func (x *txServer) mint(t *testing.T, issuer, audience, jti, eventType, subject string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: x.key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(ssf.TypSET)).
			WithHeader("kid", x.kid))
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{
		"iss": issuer, "jti": jti, "iat": time.Now().Unix(),
		"aud": []string{audience},
		"events": map[string]any{eventType: map[string]any{
			"subject": map[string]any{
				"format": "iss_sub", "iss": issuer, "sub": subject,
			},
			"event_timestamp": time.Now().Unix(),
		}},
	})
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestASignedSignalEndsRealSessions(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	tx := newTXServer(t)

	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("https://tx-%d.test", suffix)
	audience := "https://signari.test"
	external := fmt.Sprintf("ext-%d", suffix)

	// Fixture: an instance, org, user, a federated identity naming the
	// transmitter's subject, and three live sessions.
	var instanceID, orgID, userID, providerID string
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ($1,'ssf') RETURNING id::text`,
		fmt.Sprintf("https://ssf-%d.test", suffix)).Scan(&instanceID))
	must(pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1,$2,'SSF') RETURNING id::text`,
		instanceID, fmt.Sprintf("ssf%d", suffix)).Scan(&orgID))
	must(pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, sha256($2::bytea)||sha256($3::bytea), $4) RETURNING id::text`,
		orgID, fmt.Sprint(suffix), fmt.Sprint(suffix+1),
		fmt.Sprintf("u%d@ssf.test", suffix)).Scan(&userID))
	must(pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, issuer, client_id)
		VALUES ($1,$2,'TX','oidc',$3,'cid') RETURNING id::text`,
		orgID, fmt.Sprintf("tx%d", suffix), issuer).Scan(&providerID))
	_, err := pool.Exec(ctx, `
		INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4)`, providerID, userID, orgID, external)
	must(err)

	for i := 0; i < 3; i++ {
		_, err := pool.Exec(ctx, `
			INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr,
			                           auth_time, not_after)
			VALUES ($1, sha256($2::bytea), $3, $4, '1', '{pwd}', now(), now()+interval '2 hours')`,
			fmt.Sprintf("ssf-%d-%d", suffix, i), fmt.Sprintf("c%d%d", suffix, i),
			orgID, userID)
		must(err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO core.ssf_sources (org_id, display_name, issuer, jwks_uri,
		                              audience, allowed_events)
		VALUES ($1::uuid,'TX',$2,$3,$4,$5)`,
		orgID, issuer, "https://"+strings.TrimPrefix(tx.srv.URL, "https://"),
		audience, []string{ssf.EventSessionRevoked})
	must(err)

	srv := &Server{
		db:  pool,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// The transmitter's certificate is self-signed, so the fetcher uses the
		// test server's own client. In production this is an ordinary client
		// with ordinary roots.
		ssfKeys: &ssf.KeyFetcher{HTTP: tx.srv.Client()},
	}

	live := func() int {
		var n int
		must(pool.QueryRow(ctx,
			`SELECT count(*) FROM core.sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`,
			userID).Scan(&n))
		return n
	}
	if got := live(); got != 3 {
		t.Fatalf("fixture has %d live sessions, want 3", got)
	}

	post := func(token string) int {
		r := httptest.NewRequest(http.MethodPost, "/ssf/receive", strings.NewReader(token))
		w := httptest.NewRecorder()
		srv.handleSSFReceive(w, r)
		return w.Code
	}

	// A genuine event.
	code := post(tx.mint(t, issuer, audience, fmt.Sprintf("jti-a-%d", suffix), ssf.EventSessionRevoked, external))
	if code != http.StatusAccepted {
		t.Fatalf("a genuine event returned %d, want 202", code)
	}
	if got := live(); got != 0 {
		t.Fatalf("%d sessions still live after a session-revoked event", got)
	}

	// The revocation reason must name the signal, not look like a logout --
	// they mean very different things to whoever reads the audit trail.
	var reason string
	must(pool.QueryRow(ctx, `
		SELECT revocation_reason FROM core.sessions
		 WHERE user_id=$1::uuid AND revoked_at IS NOT NULL LIMIT 1`, userID).Scan(&reason))
	if reason != "shared_signal" {
		t.Fatalf("revocation_reason = %q, want shared_signal", reason)
	}

	// Replay: accepted (at-least-once delivery is normal) but recorded once.
	if c := post(tx.mint(t, issuer, audience, fmt.Sprintf("jti-b-%d", suffix), ssf.EventSessionRevoked, external)); c != http.StatusAccepted {
		t.Fatalf("second event returned %d", c)
	}
	replayJTI := fmt.Sprintf("jti-replay-%d", suffix)
	same := tx.mint(t, issuer, audience, replayJTI, ssf.EventSessionRevoked, external)
	if c := post(same); c != http.StatusAccepted {
		t.Fatalf("first send of the replay token returned %d", c)
	}
	if c := post(same); c != http.StatusAccepted {
		t.Fatalf("replay returned %d; a transmitter resending legitimately must "+
			"not be told to retry forever", c)
	}
	var n int
	must(pool.QueryRow(ctx,
		`SELECT count(*) FROM core.ssf_received r
		   JOIN core.ssf_sources src ON src.id = r.source_id
		  WHERE r.jti = $1 AND src.issuer = $2`, replayJTI, issuer).Scan(&n))
	if n != 1 {
		t.Fatalf("the replayed token was recorded %d times, want 1", n)
	}

	// RFC 8935 §2.3: "When the SET Recipient detects an error parsing,
	// validating, or authenticating a SET ... SHALL respond with an HTTP
	// Response Status Code of 400 (Bad Request)." Not 401 -- an earlier version
	// of this test asserted 401 and was asserting a conformance bug.
	if c := post(tx.mint(t, issuer, audience, fmt.Sprintf("jti-c-%d", suffix),
		ssf.EventTokenClaimsChange, external)); c != http.StatusBadRequest {
		t.Fatalf("an ungranted event type returned %d, want 400 per RFC 8935 §2.3", c)
	}
	if c := post(tx.mint(t, "https://impostor.test", audience, fmt.Sprintf("jti-d-%d", suffix),
		ssf.EventSessionRevoked, external)); c != http.StatusBadRequest {
		t.Fatalf("an unknown issuer returned %d, want 400 per RFC 8935 §2.3", c)
	}

	// Garbage.
	if c := post("not.a.token"); c != http.StatusBadRequest {
		t.Fatalf("garbage returned %d, want 400", c)
	}
}

// RFC 8935 §2.3 requires a specific error shape, and §2.4 a registered code.
func TestTheErrorResponseMatchesRFC8935(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/ssf/receive",
		strings.NewReader("not.a.token"))
	w := httptest.NewRecorder()
	(&Server{}).writeSSFErrorForTest(w)

	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (§2.3)", got)
	}
	// MUST be present. A transmitter is entitled to know what language it is
	// being told off in, and the first version omitted it.
	if got := w.Header().Get("Content-Language"); got == "" {
		t.Error("no Content-Language header; §2.3 says the response MUST include one")
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["err"] == "" {
		t.Error("no err field; §2.3 requires one")
	}
	// Registered names only, from the §2.4 table.
	registered := map[string]bool{
		"invalid_request": true, "invalid_key": true, "invalid_issuer": true,
		"invalid_audience": true, "authentication_failed": true, "access_denied": true,
	}
	if !registered[body["err"]] {
		t.Errorf("err = %q, which is not in the IANA registry (§2.4). A "+
			"transmitter matching on the code cannot know what it means", body["err"])
	}
	_ = r
}

// writeSSFErrorForTest exercises the error writer directly.
func (s *Server) writeSSFErrorForTest(w http.ResponseWriter) {
	writeSSFError(w, http.StatusBadRequest, errInvalidRequest, "for the test")
}
