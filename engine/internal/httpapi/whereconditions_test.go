package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"signari.dev/engine/internal/risk"
	"signari.dev/engine/internal/store"
)

// placeAt is a resolver that knows one country for everywhere it knows at all.
type placeAt map[string]string

func (p placeAt) Resolve(ip string) risk.Location {
	country, known := p[ip]
	return risk.Location{Country: country, Known: known}
}

// A rule on where somebody is, asked from the address a request really came from (11.09).
// The file's own tests prove the rule; this proves the engine hands it a country and a
// record, and reads neither for a policy that asks about neither.
func TestARuleIsToldWhereARequestCameFrom(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	n := time.Now().UnixNano()
	home := fmt.Sprintf("203.0.113.%d", n%100+1)
	away := fmt.Sprintf("198.51.100.%d", n%100+1)
	nowhere := fmt.Sprintf("192.0.2.%d", n%100+1)
	f.srv.geo = placeAt{home: "GB", away: "FR"}

	decide := func(ip string) bool {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.RemoteAddr = ip + ":443"
		d := f.srv.checkAccessPolicy(ctx, r, f.orgID, f.clientID, f.userID, "openid", false, nil)
		return d == nil || d.Allowed
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, `
version: 1
policies:
  - name: only-here
    require:
      from_countries: [GB]
tests:
  - {name: here, given: {client: x, country: GB}, expect: allow}
`)
	if !decide(home) {
		t.Error("an address in a listed country was refused")
	}
	if decide(away) {
		t.Error("an address in another country was allowed")
	}
	if decide(nowhere) {
		t.Error("an address nothing can place met from_countries")
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, `
version: 1
policies:
  - name: not-there
    require:
      not_from_countries: [FR]
tests:
  - {name: elsewhere, given: {client: x, country: GB}, expect: allow}
`)
	if !decide(home) || !decide(nowhere) {
		t.Error("not_from_countries refused an address with no evidence against it")
	}
	if decide(away) {
		t.Error("an address in a refused country was allowed")
	}

	applyPolicy(t, f.srv, f.pool, f.orgID, `
version: 1
policies:
  - name: keeps-its-record
    require:
      max_recent_failures: 2
tests:
  - {name: clean, given: {client: x}, expect: allow}
`)
	clearOfWindowEdge(t, signInPerIPWindow)
	if !decide(home) {
		t.Fatal("a clean address was refused")
	}
	for range 3 {
		if _, err := store.AllowRate(ctx, f.pool, "signin:fail:ip:"+budgetIP(home), 1000, signInPerIPWindow); err != nil {
			t.Fatal(err)
		}
	}
	if decide(home) {
		t.Error("an address over its failures was allowed")
	}
	if !decide(away) {
		t.Error("another address paid for it")
	}
}
