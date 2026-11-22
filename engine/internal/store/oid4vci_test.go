package store

import (
	"context"
	"testing"
)

// A token whose subject is a client, from the client-credentials grant, is
// simply not an issuance token. The lookup compared its subject as a uuid,
// which made presenting one a server error rather than a refusal.
func TestATokenForAClientIsNotAnIssuanceTokenOrAnError(t *testing.T) {
	pool := rateTestPool(t)
	ids, err := IssuableConfigurations(context.Background(), pool,
		"no-offer-minted-this-jti", "a-service-client")
	if err != nil {
		t.Fatalf("a client's token made the lookup fail: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("a token no offer minted may be exchanged for %v", ids)
	}
}
