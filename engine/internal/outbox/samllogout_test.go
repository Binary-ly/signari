package outbox

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/saml"
	"signari.dev/engine/internal/store"
)

// soapProvider is a service provider with a SOAP address, somebody with a session
// that reached it, and a server standing in for it.
type soapProvider struct {
	w                      *Worker
	pool                   *pgxpool.Pool
	orgID, userID, sid, id string
	mu                     sync.Mutex
	got                    []*http.Request
	bodies                 [][]byte
	answer                 func(w http.ResponseWriter, requestID string)
}

func answerSuccess(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/"><soap11:Body>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" InResponseTo="%s">
<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse></soap11:Body></soap11:Envelope>`,
		requestID, saml.StatusSuccess)
}

func newSOAPProvider(t *testing.T) *soapProvider {
	t.Helper()
	pool := drainTestPool(t)
	clearOutbox(t, pool)
	ctx := context.Background()
	p := &soapProvider{pool: pool, orgID: seedOrg(t, pool), answer: answerSuccess}
	p.w = drainWorker(t, pool, 10)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		doc := etree.NewDocument()
		id := ""
		if doc.ReadFromBytes(body) == nil {
			if e := doc.FindElement("//LogoutRequest"); e != nil {
				id = e.SelectAttrValue("ID", "")
			}
		}
		p.mu.Lock()
		p.got, p.bodies = append(p.got, r), append(p.bodies, body)
		answer := p.answer
		p.mu.Unlock()
		answer(w, id)
	}))
	t.Cleanup(srv.Close)
	p.w.client = withNoRedirects(srv.Client())

	key, err := p.w.keys.Active(keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO core.signing_keys (kid, instance_id, algorithm, state, public_jwk, key_ref)
		SELECT $1, instance_id, 'RS256', 'passive', '{}', 'test:in-memory'
		  FROM core.organizations WHERE id = $2::uuid`, key.KID(), p.orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, 's' || substr(gen_random_uuid()::text, 1, 8) || '@example.test',
		        decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text) ||
		               md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'))
		RETURNING id::text`, p.orgID).Scan(&p.userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `WITH sp AS (
		  INSERT INTO core.saml_providers (org_id, entity_id, display_name)
		  VALUES ($1::uuid, 'https://sp-' || gen_random_uuid() || '.test', 'SP') RETURNING id
		), u AS (
		  INSERT INTO core.saml_slo_urls (provider_id, url, binding) SELECT id, $2, 'SOAP' FROM sp
		)
		SELECT id::text FROM sp`, p.orgID, srv.URL+"/slo").Scan(&p.id); err != nil {
		t.Fatal(err)
	}
	p.sid = p.reached(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.outbox WHERE topic = $1 AND payload->>'provider_id' = $2`,
			store.SAMLLogoutTopic, p.id)
	})
	return p
}

// reached is another session of the person that reached the provider.
func (p *soapProvider) reached(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	sid := "sid-" + itoa64(time.Now().UnixNano())
	if _, err := p.pool.Exec(ctx, `INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
		VALUES ($1, $2::uuid, $3::uuid, now(), now() + interval '1 hour')`, sid, p.orgID, p.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO core.saml_session_participants
		(sid, provider_id, org_id, session_index, name_id, name_id_format)
		VALUES ($1, $2::uuid, $3::uuid, $1, 'ada@corp.test', $4)`, sid, p.id, p.orgID, saml.FullNameIDFormat("emailAddress")); err != nil {
		t.Fatal(err)
	}
	return sid
}

func (p *soapProvider) end(t *testing.T, sid, userID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.TerminateSessions(ctx, tx, sid, userID, store.ReasonLogout); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (p *soapProvider) queued(t *testing.T) (n int, payloads string) {
	t.Helper()
	if err := p.pool.QueryRow(context.Background(), `SELECT count(*), COALESCE(string_agg(payload::text, ' '), '')
		FROM core.outbox WHERE topic = $1 AND delivered_at IS NULL AND payload->>'provider_id' = $2`,
		store.SAMLLogoutTopic, p.id).Scan(&n, &payloads); err != nil {
		t.Fatal(err)
	}
	return n, payloads
}

// The whole of it, with nobody at a browser: a session ends, and the provider is told
// by a request it can verify, carrying what its assertion did.
func TestASessionEndingTellsTheProviderWithNoBrowser(t *testing.T) {
	p := newSOAPProvider(t)
	ctx := context.Background()
	p.end(t, p.sid, "")

	n, payloads := p.queued(t)
	if n != 1 {
		t.Fatalf("%d queued", n)
	}
	if strings.Contains(payloads, "ada@corp.test") {
		t.Errorf("a queue holds somebody's address: %s", payloads)
	}
	if done, err := p.w.drainSAMLLogouts(ctx); err != nil || done != 1 {
		t.Fatalf("drained %d, %v", done, err)
	}
	if n, _ := p.queued(t); n != 0 {
		t.Errorf("%d left queued after a good answer", n)
	}
	if len(p.got) != 1 {
		t.Fatalf("the provider heard %d", len(p.got))
	}
	r := p.got[0]
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/xml") ||
		r.Header.Get("SOAPAction") != saml.SOAPAction {
		t.Errorf("sent %s %q %q", r.Method, r.Header.Get("Content-Type"), r.Header.Get("SOAPAction"))
	}

	body := string(p.bodies[0])
	start := strings.Index(body, "<samlp:LogoutRequest")
	finish := strings.Index(body, "</soap11:Body>")
	if start < 0 || finish < 0 || !strings.HasPrefix(body, "<soap11:Envelope") {
		t.Fatalf("not an envelope around a request: %.300s", body)
	}
	raw := []byte(body[start:finish])
	var sent saml.LogoutRequest
	if err := saml.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.NameID != "ada@corp.test" || sent.SessionIndex != p.sid || sent.Issuer != "https://id.example.test/saml" {
		t.Errorf("it was told %q %q by %q", sent.NameID, sent.SessionIndex, sent.Issuer)
	}
	key, err := p.w.keys.Active(keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	if err := p.pool.QueryRow(ctx, `SELECT certificate FROM core.signing_keys WHERE kid = $1`, key.KID()).Scan(&der); err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := saml.VerifyEmbeddedSignature(raw, certPEM, "LogoutRequest", sent.ID); err != nil {
		t.Errorf("the request does not verify against the published certificate: %v", err)
	}
}

// A provider down, or saying no, is asked again, and one that answers something else
// than this request has not answered it.
// A provider at its organisation's endpoints knows us by the entity id of those.
func TestALogoutGoesOutAsWhoTheProviderKnows(t *testing.T) {
	p := newSOAPProvider(t)
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, `UPDATE core.saml_providers SET org_endpoint = true WHERE id = $1::uuid`, p.id); err != nil {
		t.Fatal(err)
	}
	var slug string
	if err := p.pool.QueryRow(ctx, `SELECT slug FROM core.organizations WHERE id = $1::uuid`, p.orgID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	p.end(t, p.sid, "")
	if done, err := p.w.drainSAMLLogouts(ctx); err != nil || done != 1 {
		t.Fatalf("drained %d, %v", done, err)
	}
	if len(p.bodies) != 1 {
		t.Fatalf("the provider heard %d", len(p.bodies))
	}
	if want := "/saml/org/" + slug + "</saml:Issuer>"; !strings.Contains(string(p.bodies[0]), want) {
		t.Errorf("the request does not end %q: %.400s", want, p.bodies[0])
	}
}

func TestAProviderThatDidNotTakeItIsToldAgain(t *testing.T) {
	p := newSOAPProvider(t)
	ctx := context.Background()
	p.end(t, p.sid, "")
	for name, answer := range map[string]func(http.ResponseWriter, string){
		"a 500": func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusInternalServerError) },
		"a refusal": func(w http.ResponseWriter, id string) {
			fmt.Fprintf(w, `<LogoutResponse InResponseTo="%s"><Status><StatusCode Value="%s"/></Status></LogoutResponse>`,
				id, saml.StatusRequester)
		},
		"another request's answer": func(w http.ResponseWriter, _ string) { answerSuccess(w, "_someone-elses") },
	} {
		p.mu.Lock()
		p.answer = answer
		p.mu.Unlock()
		if _, err := p.pool.Exec(ctx, `UPDATE core.outbox SET next_attempt_at = now() WHERE topic = $1`, store.SAMLLogoutTopic); err != nil {
			t.Fatal(err)
		}
		if _, err := p.w.drainSAMLLogouts(ctx); err != nil {
			t.Fatal(err)
		}
		if n, _ := p.queued(t); n != 1 {
			t.Errorf("%s: the notice was taken as delivered", name)
		}
	}
	var attempts int
	if err := p.pool.QueryRow(ctx, `SELECT attempts FROM core.outbox WHERE topic = $1 AND delivered_at IS NULL
		AND payload->>'provider_id' = $2`, store.SAMLLogoutTopic, p.id).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Errorf("%d attempts", attempts)
	}
	p.mu.Lock()
	p.answer = answerSuccess
	p.mu.Unlock()
	if _, err := p.pool.Exec(ctx, `UPDATE core.outbox SET next_attempt_at = now() WHERE topic = $1`, store.SAMLLogoutTopic); err != nil {
		t.Fatal(err)
	}
	if _, err := p.w.drainSAMLLogouts(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.queued(t); n != 0 {
		t.Error("a good answer did not end it")
	}
}

// One since disabled or given up on is not chased.
func TestAProviderSinceDisabledIsNotTold(t *testing.T) {
	p := newSOAPProvider(t)
	ctx := context.Background()
	p.end(t, p.sid, "")
	if _, err := p.pool.Exec(ctx, `UPDATE core.saml_providers SET enabled = false WHERE id = $1::uuid`, p.id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.w.drainSAMLLogouts(ctx); err != nil {
		t.Fatal(err)
	}
	if len(p.got) != 0 {
		t.Error("a disabled provider was told")
	}
	if n, _ := p.queued(t); n != 0 {
		t.Errorf("%d still queued for a provider that will never answer", n)
	}
}

// Everything that ends a person's sessions goes the one way, each session named once,
// and a session already over tells nobody anything.
func TestEverySessionThatEndsIsToldOnce(t *testing.T) {
	p := newSOAPProvider(t)
	p.reached(t)
	p.end(t, "", p.userID)
	if n, _ := p.queued(t); n != 2 {
		t.Errorf("%d queued for two sessions", n)
	}
	p.end(t, "", p.userID)
	if n, _ := p.queued(t); n != 2 {
		t.Errorf("ending them again queued more: %d", n)
	}
}

// A SOAP address is no place to send a browser.
func TestABrowserIsNeverSentToASOAPAddress(t *testing.T) {
	p := newSOAPProvider(t)
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	parts, err := store.SAMLParticipantsForSession(ctx, tx, p.sid, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || len(parts[0].SLOURLs) != 0 {
		t.Errorf("the redirect chain would visit %+v", parts)
	}
}
