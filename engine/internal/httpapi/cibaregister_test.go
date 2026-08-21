package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CIBA §4 makes `backchannel_token_delivery_mode` REQUIRED client metadata, and
// this issuer implements poll mode only — `backchannel_token_delivery_modes_supported`
// advertises `["poll"]`.
//
// RFC 7591 §2 permits a server to ignore metadata it does not recognise, and
// dynamic registration did exactly that. Ignoring THIS parameter has a specific
// consequence: a client registering for `push` was recorded as an ordinary CIBA
// client, would receive an `auth_req_id`, and would then wait for a delivery
// that never comes.
//
// The backchannel endpoint already applies this reasoning to
// `client_notification_token` — "a client that receives an auth_req_id concludes
// the mode it asked for was accepted, and would wait forever". It belongs at
// registration too, where the client can still act on being told.

// registrationToken mints one and returns the bearer value.
func registrationToken(t *testing.T, f *tokenFixture) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(tok))

	// RedeemRegistrationToken joins the policy and requires `enabled`, so a token
	// alone is not enough: registration must be switched on for the organisation.
	// That is the right shape — a stray token row cannot open an endpoint an
	// operator never enabled — and it is why this helper writes both.
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.registration_policies (org_id, enabled)
		VALUES ($1::uuid, true)
		ON CONFLICT (org_id) DO UPDATE SET enabled = true`, f.orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO core.registration_tokens (org_id, name, token_hash)
		VALUES ($1::uuid, 'test', $2)`, f.orgID, sum[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.registration_policies WHERE org_id = $1::uuid`, f.orgID)
	})
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(),
			`DELETE FROM core.registration_tokens WHERE token_hash = $1`, sum[:])
	})
	return tok
}

func registerWithMode(t *testing.T, f *tokenFixture, mode string) (int, string) {
	t.Helper()
	body := `{"redirect_uris":["https://rp.test/cb"],"client_name":"m"`
	if mode != "" {
		body += `,"backchannel_token_delivery_mode":"` + mode + `"`
	}
	body += `}`

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+registrationToken(t, f))
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestRegisteringForADeliveryModeWeDoNotSupportIsRefused(t *testing.T) {
	f := newTokenFixture(t)

	for _, mode := range []string{"ping", "push"} {
		t.Run(mode, func(t *testing.T) {
			status, body := registerWithMode(t, f, mode)
			if status == http.StatusCreated || status == http.StatusOK {
				t.Fatalf("a client registered for %q delivery was accepted; it will "+
					"receive an auth_req_id and wait for a callback this issuer never "+
					"makes: %s", mode, truncate(body, 200))
			}
			if !strings.Contains(body, "invalid_client_metadata") {
				t.Errorf("refused, but not as a metadata problem: %d %s",
					status, truncate(body, 200))
			}
			if !strings.Contains(body, "poll") {
				t.Errorf("the refusal does not say which mode IS supported, so the "+
					"client cannot act on it: %s", truncate(body, 200))
			}
		})
	}
}

// The supported mode, and an absent one, must both still register — otherwise
// the check is an outage for every CIBA client and every ordinary client.
func TestRegisteringForPollOrWithoutAModeStillWorks(t *testing.T) {
	f := newTokenFixture(t)

	for _, mode := range []string{"poll", ""} {
		name := mode
		if name == "" {
			name = "(absent)"
		}
		t.Run(name, func(t *testing.T) {
			status, body := registerWithMode(t, f, mode)
			if status != http.StatusCreated && status != http.StatusOK {
				t.Errorf("registration with delivery mode %s was refused: %d %s",
					name, status, truncate(body, 250))
			}
		})
	}
}
