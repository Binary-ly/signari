package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"signari.dev/engine/internal/oauth"
)

// An exchange in an organisation with no access policy reads neither the policy nor the
// session's factors it would be judged with (E.25): the client's lookup on this request says
// there is none, as the authorization endpoint already asks it. Both were read on every
// exchange, jwt-bearer and pre-authorized grant. Where there is a policy it is still read and
// still applies: TestAnExchangeIsRefusedWhenThePolicyDeniesTheClient and its neighbours.
func TestAnExchangeWithNoPolicyReadsNoPolicy(t *testing.T) {
	f := newTokenFixture(t)
	f.enableExchange(t)
	subject := f.subjectTokenWithDetails(t, "verifier-exchange-reads-aaaaaaaaaaaaaaaaaaaa", nil)
	trips := countRoundTrips(t, f)
	status, body := f.post(t, url.Values{
		"grant_type": {oauth.GrantTypeTokenExchange}, "client_secret": {f.exchangeSecret},
		"subject_token": {subject}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience": {exchangeAudience}, "client_id": {f.clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("the exchange answered %d: %v", status, body)
	}
	trips.mu.Lock()
	defer trips.mu.Unlock()
	for _, s := range trips.what {
		if strings.HasPrefix(s, "SELECT md5(document)") || strings.HasPrefix(s, "SELECT amr FROM core.sessions") {
			t.Errorf("an exchange in an organisation with no access policy ran %q", s)
		}
	}
}
