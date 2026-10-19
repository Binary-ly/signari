package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// `token_exchange` grants RFC 8693 exchange through the same writer as the CLI
// and the Admin API, is planned like any other field, and is left alone when
// the file omits it.
func TestApplyGrantsAndWithdrawsTokenExchange(t *testing.T) {
	ctx, pool, org := applyFixture(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	id := fmt.Sprintf("cfg-exch-%d", time.Now().UnixNano())
	apply := func(x *TokenExchange) *Plan {
		t.Helper()
		f := &File{Clients: []Client{{ClientID: id, RedirectURIs: []string{"https://gw.test/cb"}, TokenExchange: x}}}
		plan, err := BuildPlan(ctx, tx, org, f, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, tx, org, f, plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	stored := func() (bool, string) {
		t.Helper()
		var may bool
		var aud string
		if err := tx.QueryRow(ctx, `SELECT may_exchange, array_to_string(exchange_audiences, ',')
			FROM core.clients WHERE client_id = $1`, id).Scan(&may, &aud); err != nil {
			t.Fatal(err)
		}
		return may, aud
	}

	apply(&TokenExchange{Enabled: true, Audiences: []string{"https://billing.test/api"}})
	if may, aud := stored(); !may || aud != "https://billing.test/api" {
		t.Fatalf("after granting: %v %q", may, aud)
	}
	if plan := apply(nil); !plan.Empty() {
		t.Errorf("a file without token_exchange planned %+v", plan.Changes)
	}
	if may, aud := stored(); !may || aud != "https://billing.test/api" {
		t.Errorf("an omitted token_exchange changed the grant to %v %q", may, aud)
	}
	if plan := apply(&TokenExchange{Enabled: true, Audiences: []string{" https://billing.test/api"}}); !plan.Empty() {
		t.Errorf("the same grant, spelled with a space, planned %+v", plan.Changes)
	}
	plan := apply(&TokenExchange{Enabled: false})
	if len(plan.Changes) != 1 || !strings.Contains(plan.Changes[0].Detail, "token_exchange") {
		t.Errorf("withdrawing planned %+v", plan.Changes)
	}
	if may, aud := stored(); may || aud != "" {
		t.Errorf("after withdrawing: %v %q", may, aud)
	}
}

func TestATokenExchangeTheEndpointWouldRefuseIsRefusedByTheFile(t *testing.T) {
	for name, c := range map[string]Client{
		"a public client": {ClientID: "p", Public: true, RedirectURIs: []string{"https://p.test/cb"},
			TokenExchange: &TokenExchange{Enabled: true}},
		"audiences while disabled": {ClientID: "d", RedirectURIs: []string{"https://d.test/cb"},
			TokenExchange: &TokenExchange{Audiences: []string{"https://x.test"}}},
		"an audience with a space": {ClientID: "s", RedirectURIs: []string{"https://s.test/cb"},
			TokenExchange: &TokenExchange{Enabled: true, Audiences: []string{"two words"}}},
	} {
		if err := (&File{Version: 1, Org: "00000000-0000-0000-0000-000000000001", Clients: []Client{c}}).Validate(); err == nil ||
			!strings.Contains(err.Error(), "token_exchange") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
