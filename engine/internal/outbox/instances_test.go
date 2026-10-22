package outbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A process serving several instances (6.12) signs each logout token as the
// instance of the client it is for, and leaves one for an instance it does not
// serve for a process that does. Signed with the one set it had, a token for
// another instance's client was refused by the relying party, which verifies
// that instance's keys, and recorded here as delivered.

func signingSet(t *testing.T) *keys.Set {
	t.Helper()
	k, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, err := keys.NewSet(active)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// instanceWithClient is a fresh instance holding one organisation and client.
func instanceWithClient(t *testing.T, pool *pgxpool.Pool) (instanceID, clientID string) {
	t.Helper()
	ctx := context.Background()
	clientID = "inst-" + time.Now().Format("150405.000000000")
	if err := pool.QueryRow(ctx, `
		WITH i AS (
			INSERT INTO core.instances (issuer, display_name)
			VALUES ('https://ob-' || gen_random_uuid() || '.test', 'T') RETURNING id
		), o AS (
			INSERT INTO core.organizations (instance_id, slug, display_name)
			SELECT id, 'o' || substr(gen_random_uuid()::text, 1, 8), 'Org' FROM i RETURNING id, instance_id
		)
		INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash,
		                          grant_types, scopes, require_pkce)
		SELECT $1, id, 'T', 'public', '', ARRAY['authorization_code'], ARRAY['openid'], true FROM o
		RETURNING (SELECT instance_id::text FROM o)`, clientID).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core.clients WHERE client_id = $1`, clientID)
	})
	return instanceID, clientID
}

func TestALogoutTokenIsSignedAsItsClientsInstance(t *testing.T) {
	pool := drainTestPool(t)
	t.Setenv(AllowPrivateDelivery, "1")
	ctx := context.Background()
	instA, _ := instanceWithClient(t, pool)
	instB, clientB := instanceWithClient(t, pool)
	setA, setB := signingSet(t), signingSet(t)

	var received atomic.Value
	var calls atomic.Int32
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		received.Store(r.FormValue("logout_token"))
	}))
	t.Cleanup(rp.Close)

	worker := func(served ...string) *Worker {
		w := &Worker{db: pool, keys: setA, issuer: "https://a.test",
			log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			client: withNoRedirects(outboundClient(5 * time.Second))}
		for _, id := range served {
			switch id {
			case instA:
				w.AddInstance(instA, setA, "https://a.test")
			case instB:
				w.AddInstance(instB, setB, "https://b.test")
			}
		}
		return w
	}
	notice := store.LogoutNotice{ClientID: clientB, Endpoint: rp.URL, SessionID: "sid-612"}

	if err := worker(instA, instB).deliver(ctx, notice); err != nil {
		t.Fatal(err)
	}
	token, _ := received.Load().(string)
	if token == "" {
		t.Fatal("the relying party was sent no logout token")
	}
	if iss := claimsOf(t, token)["iss"]; iss != "https://b.test" {
		t.Errorf("the logout token for the second instance's client was issued by %v", iss)
	}
	if kid := headerOf(t, token)["kid"]; kid != setB.JWKS().Keys[0].KeyID {
		t.Errorf("the logout token was signed with key %v, not the client's instance's", kid)
	}

	// Not served here: not sent, and kept for a process that serves it.
	before := calls.Load()
	if err := worker(instA).deliver(ctx, notice); err == nil {
		t.Error("a process not serving the client's instance delivered its logout token")
	}
	var dropped *droppedError
	if err := worker(instA).deliver(ctx, notice); errors.As(err, &dropped) {
		t.Errorf("a notice for an instance served elsewhere was dropped: %v", err)
	}
	if calls.Load() != before {
		t.Error("the relying party was sent a token by a process not serving its instance")
	}

	// A client that no longer exists has nobody to tell.
	gone := store.LogoutNotice{ClientID: "gone-" + clientB, Endpoint: rp.URL, SessionID: "sid-612"}
	if err := worker(instA, instB).deliver(ctx, gone); !errors.As(err, &dropped) {
		t.Errorf("a notice for a client that no longer exists answered %v", err)
	}

	// Told no instances, a worker signs everything as it was built, as a
	// process serving one did.
	if err := worker().deliver(ctx, notice); err != nil {
		t.Fatal(err)
	}
	token, _ = received.Load().(string)
	if iss := claimsOf(t, token)["iss"]; iss != "https://a.test" {
		t.Errorf("a worker told no instances issued %v", iss)
	}
}
