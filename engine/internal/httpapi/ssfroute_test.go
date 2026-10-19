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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/ssf"
	"signari.dev/engine/internal/store"
)

// Two organisations trusting one transmitter: a shared upstream issues every
// customer's events under one issuer and tells them apart by audience. The
// receiver found its source by issuer alone, so whichever tenant's row came
// back first verified every event, and the other tenant's were refused or, with
// one audience between them, resolved in the wrong directory.

// ssfTenant is one organisation with a person known to the transmitter as
// subject, three live sessions, and a source for issuer addressed to audience.
type ssfTenant struct {
	orgID, userID string
}

func newSSFTenant(t *testing.T, pool *pgxpool.Pool, x *txServer, issuer, audience, subject string) ssfTenant {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	n := time.Now().UnixNano()
	var instanceID, providerID string
	var tn ssfTenant
	must(pool.QueryRow(ctx, `INSERT INTO core.instances (issuer, display_name)
		VALUES ($1,'ssf') RETURNING id::text`, fmt.Sprintf("https://ssfr-%d.test", n)).Scan(&instanceID))
	must(pool.QueryRow(ctx, `INSERT INTO core.organizations (instance_id, slug, display_name)
		VALUES ($1,$2,'SSF') RETURNING id::text`, instanceID, fmt.Sprintf("ssfr%d", n)).Scan(&tn.orgID))
	must(pool.QueryRow(ctx, `
		INSERT INTO core.users (org_id, user_handle, email)
		VALUES ($1, sha256($2::bytea)||sha256($3::bytea), $4) RETURNING id::text`,
		tn.orgID, fmt.Sprint(n), fmt.Sprint(n+1), fmt.Sprintf("u%d@ssfr.test", n)).Scan(&tn.userID))
	must(pool.QueryRow(ctx, `
		INSERT INTO core.identity_providers (org_id, slug, display_name, kind, issuer, client_id)
		VALUES ($1,$2,'TX','oidc',$3,'cid') RETURNING id::text`,
		tn.orgID, fmt.Sprintf("txr%d", n), issuer).Scan(&providerID))
	_, err := pool.Exec(ctx, `
		INSERT INTO core.federated_identities (provider_id, user_id, org_id, subject)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4)`, providerID, tn.userID, tn.orgID, subject)
	must(err)
	for i := 0; i < 3; i++ {
		_, err := pool.Exec(ctx, `
			INSERT INTO core.sessions (sid, cookie_hash, org_id, user_id, acr, amr,
			                           auth_time, not_after)
			VALUES ($1, sha256($2::bytea), $3, $4, '1', '{pwd}', now(), now()+interval '2 hours')`,
			fmt.Sprintf("ssfr-%d-%d", n, i), fmt.Sprintf("cr%d%d", n, i), tn.orgID, tn.userID)
		must(err)
	}
	must(store.AddSource(ctx, pool, tn.orgID, "TX", issuer,
		"https://"+strings.TrimPrefix(x.srv.URL, "https://"), audience,
		[]string{ssf.EventSessionRevoked}, nil))
	return tn
}

func (tn ssfTenant) live(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM core.sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`,
		tn.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ssfPost(srv *Server, token string) (int, string) {
	r := httptest.NewRequest(http.MethodPost, "/ssf/receive", strings.NewReader(token))
	w := httptest.NewRecorder()
	srv.handleSSFReceive(w, r)
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	return w.Code, body["err"]
}

func TestTwoTenantsTrustingOneTransmitterEachReceiveTheirOwnEvents(t *testing.T) {
	pool := ssfTestPool(t)
	x := newTXServer(t)
	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("https://shared-tx-%d.test", suffix)
	// The same upstream person in both tenants: the subject alone cannot say
	// whose sessions an event is about. Only the audience can.
	subject := fmt.Sprintf("person-%d", suffix)
	a := newSSFTenant(t, pool, x, issuer, "https://tenant-a.test", subject)
	b := newSSFTenant(t, pool, x, issuer, "https://tenant-b.test", subject)
	srv := &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ssfKeys: &ssf.KeyFetcher{HTTP: x.srv.Client()}}

	// The tenant registered second first: under the old lookup the first
	// tenant's row answered for both.
	if code, e := ssfPost(srv, x.mint(t, issuer, "https://tenant-b.test",
		fmt.Sprintf("b-%d", suffix), ssf.EventSessionRevoked, subject)); code != http.StatusAccepted {
		t.Fatalf("tenant B's event gave %d %s, want 202", code, e)
	}
	if got := b.live(t, pool); got != 0 {
		t.Errorf("tenant B has %d live sessions after its own session-revoked", got)
	}
	if got := a.live(t, pool); got != 3 {
		t.Fatalf("tenant A has %d live sessions after tenant B's event, want 3", got)
	}

	if code, e := ssfPost(srv, x.mint(t, issuer, "https://tenant-a.test",
		fmt.Sprintf("a-%d", suffix), ssf.EventSessionRevoked, subject)); code != http.StatusAccepted {
		t.Fatalf("tenant A's event gave %d %s, want 202", code, e)
	}
	if got := a.live(t, pool); got != 0 {
		t.Errorf("tenant A has %d live sessions after its own session-revoked", got)
	}
}

// A token addressed to both tenants names nobody in particular, and acting
// for either would be a guess about whose people to sign out.
func TestAnEventAddressedToTwoTenantsIsRefused(t *testing.T) {
	pool := ssfTestPool(t)
	x := newTXServer(t)
	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("https://shared-tx2-%d.test", suffix)
	subject := fmt.Sprintf("person-%d", suffix)
	a := newSSFTenant(t, pool, x, issuer, "https://tenant-a2.test", subject)
	b := newSSFTenant(t, pool, x, issuer, "https://tenant-b2.test", subject)
	srv := &Server{db: pool, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ssfKeys: &ssf.KeyFetcher{HTTP: x.srv.Client()}}

	code, e := ssfPost(srv, x.mintTo(t, issuer, []string{"https://tenant-a2.test", "https://tenant-b2.test"},
		fmt.Sprintf("ab-%d", suffix), ssf.EventSessionRevoked, subject))
	if code != http.StatusBadRequest || e != errInvalidAudience {
		t.Fatalf("an event addressed to two tenants gave %d %s, want 400 invalid_audience", code, e)
	}
	if a.live(t, pool) != 3 || b.live(t, pool) != 3 {
		t.Fatal("an event addressed to two tenants signed somebody out")
	}

	// §2.4's two codes, now that the pair chooses: an issuer a recipient here
	// does not accept, and an audience naming no recipient here.
	if code, e := ssfPost(srv, x.mint(t, "https://stranger.test", "https://tenant-a2.test",
		fmt.Sprintf("s-%d", suffix), ssf.EventSessionRevoked, subject)); code != http.StatusBadRequest || e != errInvalidIssuer {
		t.Errorf("an unaccepted issuer for a known recipient gave %d %s, want 400 invalid_issuer", code, e)
	}
	if code, e := ssfPost(srv, x.mint(t, issuer, "https://elsewhere.test",
		fmt.Sprintf("e-%d", suffix), ssf.EventSessionRevoked, subject)); code != http.StatusBadRequest || e != errInvalidAudience {
		t.Errorf("an audience naming nobody here gave %d %s, want 400 invalid_audience", code, e)
	}
}

// The pair belongs to one organisation, refused where it is registered, in
// any case, because the receiver's audience check ignores case.
func TestASecondTenantCannotRegisterAnotherTenantsIssuerAndAudience(t *testing.T) {
	pool := ssfTestPool(t)
	x := newTXServer(t)
	suffix := time.Now().UnixNano()
	issuer := fmt.Sprintf("https://shared-tx3-%d.test", suffix)
	a := newSSFTenant(t, pool, x, issuer, "https://tenant-a3.test", "p")
	_ = a
	b := newSSFTenant(t, pool, x, issuer, "https://tenant-b3.test", "p")

	err := store.AddSource(context.Background(), pool, b.orgID, "TX", issuer,
		"https://"+strings.TrimPrefix(x.srv.URL, "https://"), "HTTPS://TENANT-A3.TEST",
		[]string{ssf.EventSessionRevoked}, nil)
	if err == nil || !strings.Contains(err.Error(), "another organisation already accepts") {
		t.Fatalf("a second tenant took the first tenant's issuer and audience: %v", err)
	}
}
