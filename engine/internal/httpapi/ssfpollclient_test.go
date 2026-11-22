package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
	"signari.dev/engine/internal/store/storetest"
)

// What a transmitter says about an account, and pulling what it says rather than waiting
// to be sent it (12.04). The queue here behaves as RFC 8936's does: what is not
// acknowledged or reported comes back.

var ssfPollSeq atomic.Int64

// queueTX is a transmitter with a queue, serving its keys and its events over TLS.
type queueTX struct {
	*txServer
	srv *httptest.Server

	mu       sync.Mutex
	queue    map[string]string
	asks     []queueAsk
	answer   int // What the queue says, when it is not 200.
	keysDown bool
}

// queueAsk is what one poll carried.
type queueAsk struct {
	Authorization string
	Ack           []string                `json:"ack"`
	SetErrs       map[string]pollSetError `json:"setErrs"`
}

func newQueueTX(t *testing.T) *queueTX {
	t.Helper()
	q := &queueTX{txServer: newTXServer(t), queue: map[string]string{}}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: q.key.Public(), KeyID: q.kid, Algorithm: string(jose.ES256), Use: "sig",
	}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.keysDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("POST /poll", func(w http.ResponseWriter, r *http.Request) {
		var ask queueAsk
		_ = json.NewDecoder(r.Body).Decode(&ask)
		ask.Authorization = r.Header.Get("Authorization")
		q.mu.Lock()
		defer q.mu.Unlock()
		q.asks = append(q.asks, ask)
		if q.answer != 0 {
			w.WriteHeader(q.answer)
			return
		}
		for _, jti := range ask.Ack {
			delete(q.queue, jti)
		}
		for jti := range ask.SetErrs {
			delete(q.queue, jti)
		}
		_ = json.NewEncoder(w).Encode(pollResponse{Sets: q.queue})
	})
	q.srv = httptest.NewTLSServer(mux)
	t.Cleanup(q.srv.Close)
	return q
}

func (q *queueTX) put(jti, set string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queue[jti] = set
}

func (q *queueTX) queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue)
}

func (q *queueTX) set(answer int, keysDown bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.answer, q.keysDown = answer, keysDown
}

func (q *queueTX) asked() []queueAsk {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]queueAsk{}, q.asks...)
}

// signalled is a person a transmitter knows, with a password here and sessions open.
type signalled struct {
	pool                            *pgxpool.Pool
	instanceID, orgID, userID       string
	sourceID, issuer, audience, sub string
}

func newSignalled(t *testing.T, pool *pgxpool.Pool, jwksURI string, events ...string) *signalled {
	t.Helper()
	ctx := context.Background()
	n := fmt.Sprintf("%d-%d", time.Now().UnixNano(), ssfPollSeq.Add(1))
	p := &signalled{pool: pool, issuer: "https://tx-" + n + ".test", audience: "https://rx-" + n + ".test", sub: "ext-" + n}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var providerID string
	must(pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name) VALUES ($1,'ssf') RETURNING id::text`,
		"https://ssf-"+n+".test").Scan(&p.instanceID))
	must(pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1,$2,'SSF') RETURNING id::text`, p.instanceID, "ssf"+strings.ReplaceAll(n, "-", "")).Scan(&p.orgID))
	storetest.Forget(t, pool, p.orgID)
	must(pool.QueryRow(ctx, `INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, sha256($2::bytea)||sha256($3::bytea), $4) RETURNING id::text`,
		p.orgID, n, n+"x", "u"+n+"@ssf.test").Scan(&p.userID))
	must(pool.QueryRow(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, issuer, client_id)
		VALUES ($1,$2,'TX','oidc',$3,'cid') RETURNING id::text`, p.orgID, "tx"+n, p.issuer).Scan(&providerID))
	_, err := pool.Exec(ctx, `INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4)`, providerID, p.userID, p.orgID, p.sub)
	must(err)
	_, err = pool.Exec(ctx, `INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
		VALUES ($1::uuid, $2::uuid, 'x', 'argon2id')`, p.userID, p.orgID)
	must(err)
	p.openSession(t)
	must(pool.QueryRow(ctx, `INSERT INTO core.ssf_sources (org_id, display_name, issuer, jwks_uri, audience, allowed_events)
		VALUES ($1::uuid,'TX',$2,$3,$4,$5) RETURNING id::text`, p.orgID, p.issuer, jwksURI, p.audience, events).Scan(&p.sourceID))
	return p
}

func (p *signalled) openSession(t *testing.T) {
	t.Helper()
	n := fmt.Sprintf("%d-%d", time.Now().UnixNano(), ssfPollSeq.Add(1))
	if _, err := p.pool.Exec(context.Background(), `
		INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr, auth_time, not_after)
		VALUES ($1, sha256($2::bytea), $3, $4, '1', '{pwd}', now(), now()+interval '2 hours')`,
		"ssf-"+n, "c"+n, p.orgID, p.userID); err != nil {
		t.Fatal(err)
	}
}

func (p *signalled) sessions(t *testing.T) int {
	t.Helper()
	var n int
	if err := p.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.sessions WHERE user_id = $1::uuid AND revoked_at IS NULL`, p.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// passwordChange says whether the next sign-in is held for a new password, and why.
func (p *signalled) passwordChange(t *testing.T) (bool, string) {
	t.Helper()
	var must bool
	var reason *string
	if err := p.pool.QueryRow(context.Background(), `
		SELECT must_change, must_change_reason FROM core.password_credentials WHERE user_id = $1::uuid`,
		p.userID).Scan(&must, &reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return must, ""
	}
	return must, *reason
}

func (p *signalled) received(t *testing.T) (action, detail string) {
	t.Helper()
	if err := p.pool.QueryRow(context.Background(), `
		SELECT action, COALESCE(detail, '') FROM core.ssf_received WHERE source_id = $1::uuid
		 ORDER BY received_at DESC LIMIT 1`, p.sourceID).Scan(&action, &detail); err != nil {
		t.Fatal(err)
	}
	return action, detail
}

func pollingServer(t *testing.T, pool *pgxpool.Pool, q *queueTX, instanceID string) *Server {
	t.Helper()
	root, err := keys.NewRootKey("test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil)), root: root, instanceID: instanceID,
		ssfKeys:      &ssf.KeyFetcher{HTTP: q.srv.Client()},
		outboundHTTP: func(time.Duration) *http.Client { return q.srv.Client() }}
}

func TestWhatATransmitterSaysAboutAnAccountIsActedOn(t *testing.T) {
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	for _, c := range []struct {
		event            string
		endsSessions     bool
		wantsNewPassword bool
	}{
		{ssf.EventAccountDisabled, true, false},
		{ssf.EventAccountPurged, true, false},
		{ssf.EventCredentialCompromise, true, true},
		{ssf.EventCredentialChangeRequired, true, true},
		{ssf.EventAccountEnabled, false, false},
	} {
		t.Run(c.event[strings.LastIndex(c.event, "/")+1:], func(t *testing.T) {
			p := newSignalled(t, pool, q.srv.URL+"/jwks", c.event)
			srv := pollingServer(t, pool, q, p.instanceID)
			w := httptest.NewRecorder()
			srv.handleSSFReceive(w, httptest.NewRequest(http.MethodPost, "/ssf/receive",
				strings.NewReader(q.mint(t, p.issuer, p.audience, "jti-"+p.sub, c.event, p.sub))))
			if w.Code != http.StatusAccepted {
				t.Fatalf("a genuine event was answered %d: %s", w.Code, w.Body)
			}
			if live := p.sessions(t); (live == 0) != c.endsSessions {
				t.Errorf("%d sessions live; ending them is %v", live, c.endsSessions)
			}
			must, reason := p.passwordChange(t)
			if must != c.wantsNewPassword {
				t.Errorf("a new password required is %v, want %v", must, c.wantsNewPassword)
			}
			if must && reason != "reason.upstreamcompromise" {
				t.Errorf("the reason given is %q", reason)
			}
			action, detail := p.received(t)
			if strings.Contains(detail, "no handler") || action == "" {
				t.Errorf("recorded %q: %q", action, detail)
			}
		})
	}
}

func TestAPolledTransmittersEventsAreActedOnAndAcknowledged(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, p.instanceID)
	if err := store.SetSourcePoll(ctx, pool, srv.root, p.orgID, p.issuer, q.srv.URL+"/poll", "rx-client", "the-secret"); err != nil {
		t.Fatal(err)
	}
	q.put("good", q.mint(t, p.issuer, p.audience, "good-"+p.sub, ssf.EventSessionRevoked, p.sub))
	// Refused by what the source may send, and so reported rather than left to return.
	q.put("barred", q.mint(t, p.issuer, p.audience, "barred-"+p.sub, ssf.EventCredentialChange, p.sub))

	if taken := srv.pollDueSSFSources(ctx); taken != 1 {
		t.Fatalf("%d sources taken, want 1", taken)
	}
	if live := p.sessions(t); live != 0 {
		t.Fatalf("%d sessions live after a polled session-revoked", live)
	}
	asks := q.asked()
	if len(asks) < 2 {
		t.Fatalf("%d polls; the event was never acknowledged", len(asks))
	}
	if !strings.HasPrefix(asks[0].Authorization, "Basic ") {
		t.Errorf("the first poll carried %q", asks[0].Authorization)
	}
	if len(asks[1].Ack) != 1 || asks[1].Ack[0] != "good" {
		t.Errorf("acknowledged %v, want only what was acted on", asks[1].Ack)
	}
	if e, ok := asks[1].SetErrs["barred"]; !ok || e.Err != errAccessDenied {
		t.Errorf("reported %+v, want the event that was refused", asks[1].SetErrs)
	}
	if n := q.queued(); n != 0 {
		t.Errorf("%d events still queued", n)
	}
	var lastPolled *time.Time
	var problem *string
	var next time.Time
	if err := pool.QueryRow(ctx, `SELECT last_polled_at, last_poll_error, next_poll_at FROM core.ssf_sources
		WHERE id = $1::uuid`, p.sourceID).Scan(&lastPolled, &problem, &next); err != nil {
		t.Fatal(err)
	}
	if lastPolled == nil || problem != nil {
		t.Errorf("the turn recorded %v, %v", lastPolled, problem)
	}
	if time.Until(next) < 20*time.Second {
		t.Errorf("the next turn is due in %s", time.Until(next))
	}
	if taken := srv.pollDueSSFSources(ctx); taken != 0 {
		t.Errorf("a source just polled was taken again")
	}
}

func TestASourceWithNoClientIsPolledWithABearerToken(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, p.instanceID)
	if err := store.SetSourcePoll(ctx, pool, srv.root, p.orgID, p.issuer, q.srv.URL+"/poll", "", "the-secret"); err != nil {
		t.Fatal(err)
	}
	srv.pollDueSSFSources(ctx)
	if asks := q.asked(); len(asks) == 0 || asks[0].Authorization != "Bearer the-secret" {
		t.Errorf("polled with %+v", asks)
	}
}

// An outage of keys says nothing about the token: reported as invalid, it would be gone,
// and with it the only word that somebody's account was taken.
func TestAnEventThatCouldNotBeCheckedComesBack(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, p.instanceID)
	if err := store.SetSourcePoll(ctx, pool, srv.root, p.orgID, p.issuer, q.srv.URL+"/poll", "c", "s"); err != nil {
		t.Fatal(err)
	}
	token := q.mint(t, p.issuer, p.audience, "late-"+p.sub, ssf.EventSessionRevoked, p.sub)
	q.put("late", token)
	q.set(0, true)

	srv.pollDueSSFSources(ctx)
	if n := q.queued(); n != 1 {
		t.Fatalf("%d events queued: an event nobody could check was reported or acknowledged", n)
	}
	if p.sessions(t) == 0 {
		t.Fatal("sessions ended on an unchecked event")
	}
	// Pushed, it is the same: a transmitter told 400 does not try again.
	w := httptest.NewRecorder()
	srv.handleSSFReceive(w, httptest.NewRequest(http.MethodPost, "/ssf/receive", strings.NewReader(token)))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("pushed during the outage, answered %d", w.Code)
	}

	q.set(0, false)
	if _, err := pool.Exec(ctx, `UPDATE core.ssf_sources SET next_poll_at = now() WHERE id = $1::uuid`, p.sourceID); err != nil {
		t.Fatal(err)
	}
	srv.pollDueSSFSources(ctx)
	if live := p.sessions(t); live != 0 {
		t.Errorf("%d sessions live once the keys came back", live)
	}
	if n := q.queued(); n != 0 {
		t.Errorf("%d events queued once the keys came back", n)
	}
}

// One transmitter's credential buys no say over another's people, whichever keys verify:
// two sources may trust keys in common, and only the turn says who was asked.
func TestAPolledTransmitterSpeaksOnlyForItself(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	asked := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	other := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, "")
	due := &store.DueSSFPoll{ID: asked.sourceID, URL: q.srv.URL + "/poll", ClientID: "c", Secret: "s"}
	q.put("foreign", q.mint(t, other.issuer, other.audience, "foreign-"+other.sub, ssf.EventSessionRevoked, other.sub))

	if err := srv.pollSSFSource(ctx, due); err != nil {
		t.Fatal(err)
	}
	if live := other.sessions(t); live == 0 {
		t.Fatal("a transmitter ended the sessions of a source it does not speak for")
	}
	asks := q.asked()
	if e, ok := asks[len(asks)-1].SetErrs["foreign"]; !ok || e.Err != errInvalidIssuer {
		t.Errorf("reported %+v", asks[len(asks)-1].SetErrs)
	}
}

func TestAFailedTurnIsKeptAndClearedByTheNext(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, p.instanceID)
	if err := store.SetSourcePoll(ctx, pool, srv.root, p.orgID, p.issuer, q.srv.URL+"/poll", "c", "s"); err != nil {
		t.Fatal(err)
	}
	problem := func() string {
		t.Helper()
		got, err := store.Sources(ctx, pool, p.orgID)
		if err != nil || len(got) != 1 {
			t.Fatalf("%v, %d sources", err, len(got))
		}
		if got[0].LastPolledAt == nil {
			t.Fatal("the turn left no time")
		}
		return got[0].LastPollError
	}
	again := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE core.ssf_sources SET next_poll_at = now() WHERE id = $1::uuid`, p.sourceID); err != nil {
			t.Fatal(err)
		}
		srv.pollDueSSFSources(ctx)
	}
	q.set(http.StatusUnauthorized, false)
	srv.pollDueSSFSources(ctx)
	if got := problem(); !strings.Contains(got, "401") {
		t.Fatalf("recorded %q", got)
	}
	q.set(0, false)
	again()
	if got := problem(); got != "" {
		t.Errorf("a good turn left %q", got)
	}
}

func TestOnlyWhatIsDuePolledAndEnabledHereIsClaimed(t *testing.T) {
	ctx := context.Background()
	pool := ssfTestPool(t)
	q := newQueueTX(t)
	p := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	srv := pollingServer(t, pool, q, p.instanceID)
	claim := func(instance string) *store.DueSSFPoll {
		t.Helper()
		due, err := store.ClaimSSFPoll(ctx, pool, srv.root, instance, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return due
	}
	if due := claim(p.instanceID); due != nil {
		t.Fatalf("a source nobody asked to poll was claimed: %+v", due)
	}
	if err := store.SetSourcePoll(ctx, pool, srv.root, p.orgID, p.issuer, q.srv.URL+"/poll", "c", "the-secret"); err != nil {
		t.Fatal(err)
	}
	var sealed string
	if err := pool.QueryRow(ctx, `SELECT encode(poll_secret_sealed, 'escape') FROM core.ssf_sources WHERE id = $1::uuid`,
		p.sourceID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "the-secret") {
		t.Fatal("the credential was stored in clear")
	}

	other := newSignalled(t, pool, q.srv.URL+"/jwks", ssf.EventSessionRevoked)
	if due := claim(other.instanceID); due != nil {
		t.Fatalf("another instance claimed %+v", due)
	}
	if err := store.SetSSFSourceEnabled(ctx, pool, p.orgID, p.issuer, false); err != nil {
		t.Fatal(err)
	}
	if due := claim(p.instanceID); due != nil {
		t.Fatalf("a disabled source was claimed: %+v", due)
	}
	if err := store.SetSSFSourceEnabled(ctx, pool, p.orgID, p.issuer, true); err != nil {
		t.Fatal(err)
	}
	due := claim(p.instanceID)
	if due == nil || due.ID != p.sourceID || due.ClientID != "c" || due.Secret != "the-secret" {
		t.Fatalf("claimed %+v", due)
	}
	if again := claim(p.instanceID); again != nil {
		t.Fatalf("claimed twice in a turn: %+v", again)
	}

	if err := store.SetSourcePoll(ctx, pool, nil, p.orgID, p.issuer, "", "", ""); err != nil {
		t.Fatal(err)
	}
	var left bool
	if err := pool.QueryRow(ctx, `SELECT poll_secret_sealed IS NOT NULL OR poll_client_id IS NOT NULL
		FROM core.ssf_sources WHERE id = $1::uuid`, p.sourceID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left {
		t.Error("stopping kept the credential")
	}
	if due := claim(p.instanceID); due != nil {
		t.Fatalf("a stopped source was claimed: %+v", due)
	}
	if err := store.SetSourcePoll(ctx, pool, nil, p.orgID, "https://nobody.test", "", "", ""); err != store.ErrSourceUnknown {
		t.Errorf("an unknown issuer gave %v", err)
	}
}
