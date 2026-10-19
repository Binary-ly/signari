package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The account page lists the person's passkeys and offers to add and remove
// them. Registration and removal existed as endpoints, and passkey.js could
// drive both, and no page offered either, so nobody could add a passkey.
func TestTheAccountPageOffersPasskeys(t *testing.T) {
	f, cookie := enrolFixture(t)
	name := fmt.Sprintf("work key %d", time.Now().UnixNano())
	var id string
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO core.webauthn_credentials
			(user_id, org_id, credential_id, public_key, rp_id, friendly_name, is_discoverable)
		VALUES ($1::uuid, $2::uuid, decode(md5(gen_random_uuid()::text),'hex'),
		        '\x02'::bytea, 'localhost', $3, true)
		RETURNING id::text`, f.userID, f.orgID, name).Scan(&id); err != nil {
		t.Fatal(err)
	}

	rec := accountGET(f, cookie, "/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("the account page answered %d", rec.Code)
	}
	page := rec.Body.String()
	for _, want := range []string{
		name,                                  // the passkey is listed
		`data-id="` + id + `"`,                // with a control that removes it
		`id="passkey-register"`,               // and one that adds another
		`id="passkey-csrf"`,                   // the token removal must send
		`<script src="/passkey.js"></script>`, // the script that drives both
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the account page lacks %s", want)
		}
	}
	// The script is same-origin and nothing is inline, so the page's own CSP
	// must allow exactly that, or the controls stay hidden and inert.
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("the account page's CSP %q lacks %s; passkey.js would be blocked", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Error("the account page allows inline script")
	}

	// The script wires both controls, and starts no sign-in ceremony on a page
	// with no field asking for one, which would hold the API's one ceremony and
	// refuse the create() the button starts.
	js := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(js, httptest.NewRequest(http.MethodGet, "/passkey.js", nil))
	body := js.Body.String()
	for _, want := range []string{"signariRemovePasskey", `getElementById("passkey-register")`,
		`input[autocomplete~="webauthn"]`} {
		if !strings.Contains(body, want) {
			t.Errorf("passkey.js lacks %s", want)
		}
	}
}
