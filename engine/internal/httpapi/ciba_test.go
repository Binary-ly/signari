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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/clients"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// CIBA Core 1.0, end to end and adversarially.
//
// The flow makes a prompt appear on somebody else's device and then hands
// tokens to whoever holds the auth_req_id. Both halves of that sentence are
// attack surface: the first is a way to harass or phish a person who is not
// present, and the second is a bearer credential polled over an open endpoint.
//
// So the cases below are mostly refusals. The happy path exists to stop the
// refusals passing because nothing works at all.

type cibaFixture struct {
	srv      *Server
	pool     *pgxpool.Pool
	orgID    string
	userID   string
	email    string
	clientID string
	secret   string
	// otherClient is a second registered client, for the tests about one
	// client's auth_req_id being presented by another.
	otherClient string
	otherSecret string
	// otherUser is a second account, for the tests about approving a request
	// that belongs to somebody else.
	otherUserID string
}

func newCIBAFixture(t *testing.T) *cibaFixture {
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

	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(oidc.Config{
		Issuer: "https://ciba-test.example", Keys: set, AllowInsecureIssuer: true,
	}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &cibaFixture{srv: srv, pool: pool}
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://cb-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'c' || substr(gen_random_uuid()::text,1,8), 'Org' FROM i RETURNING id
		)
		INSERT INTO core.users (org_id, email, user_handle)
		SELECT id, 'c'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		       decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		              md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')
		FROM o RETURNING org_id::text, id::text, email`).
		Scan(&f.orgID, &f.userID, &f.email); err != nil {
		t.Fatalf("fixture user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 'other'||substr(gen_random_uuid()::text,1,8)||'@example.test',
		        decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		               md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex'))
		RETURNING id::text`, f.orgID).Scan(&f.otherUserID); err != nil {
		t.Fatalf("fixture second user: %v", err)
	}

	suffix := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	f.clientID, f.secret = f.registerClient(t, "ciba-"+suffix, true)
	f.otherClient, f.otherSecret = f.registerClient(t, "ciba-other-"+suffix, true)

	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DELETE FROM core.device_authorizations WHERE org_id = $1::uuid`, f.orgID)
		_, _ = pool.Exec(c, `DELETE FROM core.sessions WHERE org_id = $1::uuid`, f.orgID)
		_, _ = pool.Exec(c, `DELETE FROM core.clients WHERE client_id = ANY($1)`,
			[]string{f.clientID, f.otherClient})
	})
	return f
}

// registerClient makes a confidential client, optionally with the CIBA grant.
func (f *cibaFixture) registerClient(t *testing.T, id string, withCIBA bool) (string, string) {
	t.Helper()
	secret := "s-" + id + "-" + strings.Repeat("x", 24)
	hash, ok := clients.HashSecret(secret)
	if !ok {
		t.Fatal("hashing the fixture client secret")
	}
	grants := []string{"authorization_code", "refresh_token"}
	if withCIBA {
		grants = append(grants, "urn:openid:params:grant-type:ciba")
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.clients (client_id, org_id, display_name, client_type,
		                          client_secret_hash, grant_types, scopes, require_pkce)
		VALUES ($1,$2,'T','confidential',$3,$4, ARRAY['openid','profile'], false)`,
		id, f.orgID, hash, grants); err != nil {
		t.Fatalf("fixture client: %v", err)
	}
	return id, secret
}

// backchannel posts a backchannel authentication request.
func (f *cibaFixture) backchannel(t *testing.T, clientID, secret string,
	form url.Values) (int, map[string]any) {
	t.Helper()
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/backchannel",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.handleBackchannelAuth(rec, req)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// goodRequest is a request with nothing wrong with it.
func (f *cibaFixture) goodRequest() url.Values {
	return url.Values{"scope": {"openid profile"}, "login_hint": {f.email}}
}

// poll redeems an auth_req_id at the token endpoint.
func (f *cibaFixture) poll(t *testing.T, clientID, authReqID string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {authReqID},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.srv.handleCIBAGrant(rec, req, clientID)

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// request runs a successful backchannel request and returns the auth_req_id.
func (f *cibaFixture) request(t *testing.T) string {
	t.Helper()
	code, body := f.backchannel(t, f.clientID, f.secret, f.goodRequest())
	if code != http.StatusOK {
		t.Fatalf("backchannel request failed: %d %v", code, body)
	}
	id, _ := body["auth_req_id"].(string)
	if id == "" {
		t.Fatalf("no auth_req_id in %v", body)
	}
	return id
}

// approve marks a request approved, as the person would.
//
// Through a real session, because that is the only way the approval screen can
// be reached and because the id_token minted afterwards derives its acr and amr
// from that session -- an approval with no session behind it would assert an
// authentication that never happened.
func (f *cibaFixture) approve(t *testing.T, authReqID, asUser string) error {
	t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id::text FROM core.device_authorizations WHERE device_code_hash = $1`,
		store.HashToken(authReqID)).Scan(&id); err != nil {
		t.Fatalf("finding the request: %v", err)
	}
	return store.DecideBackchannel(context.Background(), f.pool, id, asUser,
		f.sessionFor(t, asUser), true)
}

// sessionFor gives a user a live session and returns its sid.
func (f *cibaFixture) sessionFor(t *testing.T, userID string) string {
	t.Helper()
	sid := "ciba-sid-" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr,
		                           auth_time, not_after)
		VALUES ($1, decode(md5($1),'hex'), $2::uuid, $3::uuid, '1', ARRAY['pwd'],
		        now(), now() + interval '1 hour')`, sid, f.orgID, userID); err != nil {
		t.Fatalf("creating a session for the approver: %v", err)
	}
	return sid
}

// clearPollClock removes the polling interval so a test can poll again at once.
// The interval is exercised on purpose in its own test; elsewhere it is noise.
func (f *cibaFixture) clearPollClock(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE core.device_authorizations SET last_polled_at = NULL WHERE org_id = $1::uuid`,
		f.orgID); err != nil {
		t.Fatal(err)
	}
}

// --- the happy path --------------------------------------------------------

func TestACIBARequestBecomesTokensOnceApproved(t *testing.T) {
	f := newCIBAFixture(t)

	authReqID := f.request(t)

	// Before approval, §11: authorization_pending.
	code, body := f.poll(t, f.clientID, authReqID)
	if code != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("before approval: %d %v, want 400 authorization_pending", code, body)
	}

	if err := f.approve(t, authReqID, f.userID); err != nil {
		t.Fatalf("approving: %v", err)
	}
	f.clearPollClock(t)

	code, body = f.poll(t, f.clientID, authReqID)
	if code != http.StatusOK {
		t.Fatalf("after approval: %d %v", code, body)
	}
	if body["access_token"] == nil {
		t.Errorf("no access token in %v", body)
	}
	if body["id_token"] == nil {
		t.Error("openid was requested and no id_token came back")
	}
}

// TestAnAuthReqIDIsSingleUse -- it is a bearer credential, and a second
// redemption must not produce a second set of tokens.
func TestAnAuthReqIDIsSingleUse(t *testing.T) {
	f := newCIBAFixture(t)
	authReqID := f.request(t)
	if err := f.approve(t, authReqID, f.userID); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	if code, body := f.poll(t, f.clientID, authReqID); code != http.StatusOK {
		t.Fatalf("first redemption: %d %v", code, body)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatal("an auth_req_id was redeemed twice; whoever replays it gets a second " +
			"set of tokens for an approval the person gave once")
	}
	if body["error"] != "expired_token" {
		t.Errorf("second redemption answered %v, want expired_token", body["error"])
	}
}

// --- who may ask -----------------------------------------------------------

func TestAnUnauthenticatedClientCannotStartACIBARequest(t *testing.T) {
	f := newCIBAFixture(t)

	code, body := f.backchannel(t, f.clientID, "", f.goodRequest())
	if code == http.StatusOK {
		t.Fatal("a request with no client secret was accepted; this endpoint makes a " +
			"prompt appear on somebody's phone, so an open one is a way to harass " +
			"or phish them")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 (CIBA 13 assigns 401 to invalid_client)", code)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error %v, want invalid_client", body["error"])
	}
}

func TestAWrongClientSecretCannotStartACIBARequest(t *testing.T) {
	f := newCIBAFixture(t)
	code, body := f.backchannel(t, f.clientID, "not-the-secret", f.goodRequest())
	if code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("%d %v, want 401 invalid_client", code, body)
	}
}

func TestAClientWithoutTheGrantIsRefused(t *testing.T) {
	f := newCIBAFixture(t)
	id, secret := f.registerClient(t, "ciba-nogrant-"+
		strings.ReplaceAll(time.Now().Format("150405.000000"), ".", ""), false)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.clients WHERE client_id = $1`, id)
	})

	code, body := f.backchannel(t, id, secret, f.goodRequest())
	if code == http.StatusOK {
		t.Fatal("a client not registered for the CIBA grant started a CIBA request")
	}
	if body["error"] != "unauthorized_client" {
		t.Errorf("error %v, want unauthorized_client (13)", body["error"])
	}
}

// --- what may be asked -----------------------------------------------------

func TestTheHintRulesAreEnforced(t *testing.T) {
	f := newCIBAFixture(t)

	for _, c := range []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "no hint at all",
			form: url.Values{"scope": {"openid"}},
			want: "invalid_request",
		},
		{
			// 7.1: "one (and only one) of the hints". Two answers to "who" is not
			// a question this server is entitled to resolve by picking.
			name: "two hints",
			form: url.Values{"scope": {"openid"},
				"login_hint": {f.email}, "id_token_hint": {"ey.J.x"}},
			want: "invalid_request",
		},
		{
			name: "no scope",
			form: url.Values{"login_hint": {f.email}},
			want: "invalid_request",
		},
		{
			// 7.1: "CIBA authentication requests MUST contain the openid scope".
			name: "scope without openid",
			form: url.Values{"scope": {"profile"}, "login_hint": {f.email}},
			want: "invalid_scope",
		},
		{
			name: "a scope the client is not registered for",
			form: url.Values{"scope": {"openid admin"}, "login_hint": {f.email}},
			want: "invalid_scope",
		},
		{
			// 13: unknown_user_id, distinct from invalid_request, so the client
			// can tell "wrong person" from "malformed".
			name: "a hint matching nobody",
			form: url.Values{"scope": {"openid"}, "login_hint": {"nobody@example.test"}},
			want: "unknown_user_id",
		},
		{
			// Ping/push. Accepting this would hand back an auth_req_id and leave
			// the client waiting for a notification that never comes.
			name: "client_notification_token, which means ping or push",
			form: url.Values{"scope": {"openid"}, "login_hint": {f.email},
				"client_notification_token": {strings.Repeat("t", 32)}},
			want: "invalid_request",
		},
		{
			// We advertise backchannel_user_code_parameter_supported: false.
			name: "user_code when we do not advertise support",
			form: url.Values{"scope": {"openid"}, "login_hint": {f.email},
				"user_code": {"1234"}},
			want: "invalid_request",
		},
		{
			name: "a duplicated parameter",
			form: url.Values{"scope": {"openid", "openid profile"},
				"login_hint": {f.email}},
			want: "invalid_request",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body := f.backchannel(t, f.clientID, f.secret, c.form)
			if code == http.StatusOK {
				t.Fatalf("accepted: %v", body)
			}
			if body["error"] != c.want {
				t.Errorf("error %v, want %s", body["error"], c.want)
			}
		})
	}
}

// TestABindingMessageCannotRestructureTheApprovalScreen.
//
// The binding message is rendered beside "do you want to allow this". A newline
// or a bidirectional override in it is a way to make the screen say something
// other than what it appears to say, to a person about to approve access to
// their own account.
func TestABindingMessageCannotRestructureTheApprovalScreen(t *testing.T) {
	f := newCIBAFixture(t)

	for _, bad := range []struct{ name, msg string }{
		{"a line break", "Transfer £40\nApproved by your bank"},
		{"a carriage return", "Pay £5\rPay £5000"},
		{"a control character", "Pay \x00 now"},
		{"a right-to-left override", "Pay ‮0004£"},
		{"an isolate", "Pay ⁦something else⁩"},
		{"far too long", strings.Repeat("a", 200)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			form := f.goodRequest()
			form.Set("binding_message", bad.msg)
			code, body := f.backchannel(t, f.clientID, f.secret, form)
			if code == http.StatusOK {
				t.Fatalf("accepted a binding message containing %s", bad.name)
			}
			if body["error"] != "invalid_binding_message" {
				t.Errorf("error %v, want invalid_binding_message (13 defines it "+
					"precisely so the client is told which parameter to fix)", body["error"])
			}
		})
	}

	// And an ordinary one is accepted, so the check above is not simply refusing
	// every binding message.
	form := f.goodRequest()
	form.Set("binding_message", "Transfer 40.00 GBP to Alice")
	if code, body := f.backchannel(t, f.clientID, f.secret, form); code != http.StatusOK {
		t.Fatalf("a perfectly ordinary binding message was refused: %d %v", code, body)
	}
}

// --- who may answer, and who may collect -----------------------------------

// TestOnlyTheNamedSubjectCanApprove is the property the whole flow rests on.
//
// The client names a person; a prompt is shown to that person; nobody else's
// approval may complete it. If another signed-in user could approve, then any
// account on the deployment could authorise a token issued as somebody else.
func TestOnlyTheNamedSubjectCanApprove(t *testing.T) {
	f := newCIBAFixture(t)
	authReqID := f.request(t)

	if err := f.approve(t, authReqID, f.otherUserID); err == nil {
		t.Fatal("a different user approved a request naming somebody else; that is a " +
			"token issued as the named subject on a stranger's say-so")
	}

	// Still pending, not consumed by the failed attempt.
	f.clearPollClock(t)
	if code, body := f.poll(t, f.clientID, authReqID); body["error"] != "authorization_pending" {
		t.Errorf("after a rejected approval the request is %d %v, want still pending",
			code, body)
	}
}

// TestAnAuthReqIDIsBoundToTheClientThatAskedForIt.
func TestAnAuthReqIDIsBoundToTheClientThatAskedForIt(t *testing.T) {
	f := newCIBAFixture(t)
	authReqID := f.request(t)
	if err := f.approve(t, authReqID, f.userID); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.otherClient, authReqID)
	if code == http.StatusOK {
		t.Fatal("another client redeemed this auth_req_id and received tokens for a " +
			"person who approved a different application")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error %v, want invalid_grant", body["error"])
	}

	// The legitimate client must still be able to collect: a failed attempt by
	// somebody else must not burn the approval.
	f.clearPollClock(t)
	if code, body := f.poll(t, f.clientID, authReqID); code != http.StatusOK {
		t.Fatalf("the real client could no longer collect after another client tried: "+
			"%d %v", code, body)
	}
}

// TestADeniedRequestSaysSo.
func TestADeniedRequestSaysSo(t *testing.T) {
	f := newCIBAFixture(t)
	authReqID := f.request(t)

	var id string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id::text FROM core.device_authorizations WHERE device_code_hash = $1`,
		store.HashToken(authReqID)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideBackchannel(context.Background(), f.pool, id, f.userID,
		f.sessionFor(t, f.userID), false); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatal("a denied request produced tokens")
	}
	if body["error"] != "access_denied" {
		t.Errorf("error %v, want access_denied", body["error"])
	}
}

// --- the polling discipline ------------------------------------------------

// TestPollingTooFastIsSlowedAndTheIntervalGrows.
//
// 11: "A variant of authorization_pending ... the interval MUST be increased
// by at least 5 seconds for this and all subsequent requests." The increase is
// the part usually skipped, because a client that ignores slow_down is
// indistinguishable from one that obeys it unless the server actually applies it.
func TestPollingTooFastIsSlowedAndTheIntervalGrows(t *testing.T) {
	f := newCIBAFixture(t)
	authReqID := f.request(t)

	// First poll sets the clock.
	if _, body := f.poll(t, f.clientID, authReqID); body["error"] != "authorization_pending" {
		t.Fatalf("first poll: %v", body)
	}
	before := f.interval(t, authReqID)

	// Second poll, immediately.
	code, body := f.poll(t, f.clientID, authReqID)
	if body["error"] != "slow_down" {
		t.Fatalf("polling immediately answered %v, want slow_down (%d)", body["error"], code)
	}
	after := f.interval(t, authReqID)
	if after < before+5 {
		t.Errorf("the interval went %d -> %d; 11 requires an increase of at least "+
			"5 seconds, and without it slow_down is advice the client is free to ignore",
			before, after)
	}
}

func (f *cibaFixture) interval(t *testing.T, authReqID string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT interval_s FROM core.device_authorizations WHERE device_code_hash = $1`,
		store.HashToken(authReqID)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- flow confusion --------------------------------------------------------

// TestADeviceCodeCannotBeRedeemedThroughTheCIBAGrant.
//
// Both flows keep their secret in the same column, because they share the
// polling discipline. That sharing is only safe if the two are distinguished
// where it matters, and this is where.
func TestADeviceCodeCannotBeRedeemedThroughTheCIBAGrant(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	deviceCode := "device-code-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	userCode := "ABCDEFGH"
	if _, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID,
		"openid", nil, store.HashToken(deviceCode), store.HashToken(userCode),
		5, 10*time.Minute); err != nil {
		t.Fatalf("creating a device authorization: %v", err)
	}

	code, body := f.poll(t, f.clientID, deviceCode)
	if code == http.StatusOK {
		t.Fatal("a device_code was redeemed through the CIBA grant")
	}
	if body["error"] != "expired_token" {
		t.Errorf("error %v; a device code presented to the CIBA grant should be "+
			"unrecognised, not merely unapproved", body["error"])
	}
}

// --- discovery honesty -----------------------------------------------------

// TestDiscoveryDescribesTheCIBAWeActuallyImplement.
//
// The rule for this whole codebase: a capability enters discovery once it works.
// The delivery modes are the specific trap -- listing ping or push would make a
// client wait for a callback that never arrives, and it would look like our bug
// rather than its misconfiguration.
func TestDiscoveryDescribesTheCIBAWeActuallyImplement(t *testing.T) {
	f := newCIBAFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	f.srv.handleDiscovery(rec, req)

	var md map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md["backchannel_authentication_endpoint"] == nil {
		t.Error("CIBA is implemented and the backchannel endpoint is not advertised")
	}
	// Poll and ping, and push deliberately absent. The rule this test enforces is
	// not "advertise little" but "advertise exactly what is enforced": ping is
	// backed by a parked outbox row released when the person decides, and a ping
	// client that sends no notification token is refused rather than issued an
	// auth_req_id it would wait on forever.
	modes, _ := md["backchannel_token_delivery_modes_supported"].([]any)
	got := map[string]bool{}
	for _, m := range modes {
		s, _ := m.(string)
		got[s] = true
	}
	if !got["poll"] || !got["ping"] || len(modes) != 2 {
		t.Errorf("delivery modes = %v, want exactly poll and ping", modes)
	}
	if got["push"] {
		t.Error("push is advertised and not implemented; it hands the token itself " +
			"to the notification endpoint and has no code path here")
	}
	if v, ok := md["backchannel_user_code_parameter_supported"].(bool); !ok || v {
		t.Errorf("backchannel_user_code_parameter_supported = %v; the endpoint "+
			"refuses user_code, so this must be an explicit false", md["backchannel_user_code_parameter_supported"])
	}
	grants, _ := md["grant_types_supported"].([]any)
	found := false
	for _, g := range grants {
		if g == "urn:openid:params:grant-type:ciba" {
			found = true
		}
	}
	if !found {
		t.Error("the CIBA grant is accepted at the token endpoint and not advertised")
	}
}

// TestAnApprovedButExpiredRequestYieldsNothing.
//
// The shared poll path (PollDeviceCode, used by both RFC 8628 and CIBA) selects
// the row WITHOUT an expiry filter and then checks the deadline in Go. Remove
// that check and an approved-but-expired authorization mints tokens: nothing
// else catches it, because LookupUserCode's `expires_at > now()` guards the
// APPROVAL screen, not the poll.
//
// The sequence is ordinary rather than contrived — somebody approves on their
// phone, the device is asleep or offline, and it polls twenty minutes later.
// RFC 8628 §3.5 defines `expired_token` precisely so that stops working, and
// CIBA §11 repeats it.
//
// Found by mutation. The device flow has no store-level tests of its own; the
// other guarantees on this path — the polling interval, the client binding, the
// single use — are covered only because the CIBA tests above exercise the same
// function.
func TestAnApprovedButExpiredRequestYieldsNothing(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	authReqID := f.request(t)
	if err := f.approve(t, authReqID, f.userID); err != nil {
		t.Fatalf("approving: %v", err)
	}

	// Approved, then time passes. Expiry is moved rather than waited for.
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.device_authorizations
		SET expires_at = now() - interval '1 minute', last_polled_at = NULL
		WHERE device_code_hash = $1`, store.HashToken(authReqID)); err != nil {
		t.Fatal(err)
	}

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatal("an approved authorization that had since expired produced tokens; " +
			"the deadline is what bounds how long an approval stays spendable")
	}
	if body["error"] != "expired_token" {
		t.Errorf("error %v, want expired_token", body["error"])
	}

	// The same must hold for the device flow, which shares this code path.
	deviceCode := "dc-expired-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	userCode := "EXPIREDX"
	id, err := store.CreateDeviceAuthorization(ctx, f.pool, f.orgID, f.clientID,
		"openid", nil, store.HashToken(deviceCode), store.HashToken(userCode),
		5, 10*time.Minute)
	if err != nil {
		t.Fatalf("creating a device authorization: %v", err)
	}
	if err := store.ApproveDeviceAuthorization(ctx, f.pool, id, f.userID,
		f.sessionFor(t, f.userID)); err != nil {
		t.Fatalf("approving the device authorization: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.device_authorizations
		SET expires_at = now() - interval '1 minute', last_polled_at = NULL
		WHERE id = $1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PollDeviceCode(ctx, f.pool, store.HashToken(deviceCode),
		f.clientID, "device"); err == nil {
		t.Fatal("an approved device authorization that had since expired was redeemed")
	}
}

func TestAnApprovalDiesWithTheSessionItWasMadeFrom(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	authReqID := f.request(t)

	// The session the approval is made from. `approve` records it against the
	// authorization, exactly as a real approval on a phone would.
	sid := f.sessionFor(t, f.userID)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.device_authorizations
		SET status = 'approved', user_id = $2::uuid, sid = $3
		WHERE device_code_hash = $1`, store.HashToken(authReqID), f.userID, sid); err != nil {
		t.Fatalf("approving: %v", err)
	}

	// That session ends before the client polls — an administrator revoking it,
	// the user signing out everywhere, or an upstream Shared Signals transmitter
	// reporting it compromised all arrive here.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TerminateSessions(ctx, tx, sid, "", store.ReasonAdminRevoke); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatalf("an approval whose session had been revoked still produced tokens "+
			"(%v). Revoking a session, or disabling the account behind it, must "+
			"stop a pending approval from being spendable", body["access_token"] != nil)
	}
	if body["error"] != "expired_token" && body["error"] != "invalid_grant" &&
		body["error"] != "access_denied" {
		t.Errorf("refused with %v, which is not about the approval being dead: %v",
			body["error"], body)
	}
}

// A session that simply ran out is as dead as one somebody revoked.
//
// Mutation found this: changing the liveness query to check `revoked_at` alone
// and ignore `not_after` passed every test, because they all revoke rather than
// expire. The case is real — a session near the end of its lifetime approves a
// request, and the ten-minute authorization outlives it.
func TestAnApprovalDiesWithAnExpiredSessionToo(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	authReqID := f.request(t)
	sid := f.sessionFor(t, f.userID)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.device_authorizations
		SET status = 'approved', user_id = $2::uuid, sid = $3
		WHERE device_code_hash = $1`, store.HashToken(authReqID), f.userID, sid); err != nil {
		t.Fatal(err)
	}

	// Not revoked — simply past its deadline.
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.sessions SET not_after = now() - interval '1 minute'
		WHERE sid = $1`, sid); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatal("an approval whose session had expired still produced tokens; " +
			"a session that ran out is as dead as one that was revoked")
	}
	if body["error"] != "access_denied" {
		t.Errorf("error is %v, want access_denied", body["error"])
	}
}

// An approval that records no session is refused cleanly, not with a 500.
//
// The liveness check first skipped the empty-sid case, on the reasoning that
// reading "no session" as "revoked" would refuse an approval nobody revoked.
// Writing this test showed the branch cannot arise and could not succeed if it
// did: approval always records a session, and one without a session fails
// downstream with a server error rather than issuing tokens.
//
// So the special case protected nothing and turned an impossible state into a
// 500. The check now runs unconditionally, and this pins the difference between
// "refused" and "crashed" — which is what an operator reading logs cares about.
func TestAnApprovalWithNoRecordedSessionIsRefusedNotCrashed(t *testing.T) {
	f := newCIBAFixture(t)
	ctx := context.Background()

	authReqID := f.request(t)
	if _, err := f.pool.Exec(ctx, `
		UPDATE core.device_authorizations
		SET status = 'approved', user_id = $2::uuid, sid = NULL
		WHERE device_code_hash = $1`, store.HashToken(authReqID), f.userID); err != nil {
		t.Fatal(err)
	}
	f.clearPollClock(t)

	code, body := f.poll(t, f.clientID, authReqID)
	if code == http.StatusOK {
		t.Fatal("an approval with no recorded session produced tokens")
	}
	if body["error"] == "server_error" {
		t.Errorf("refused with server_error: an impossible state should be a "+
			"refusal, not a crash: %v", body)
	}
	if body["error"] != "access_denied" {
		t.Errorf("error is %v, want access_denied", body["error"])
	}
}
