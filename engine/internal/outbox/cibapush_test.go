package outbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// Push delivery, CIBA Core 1.0 §10.3.
//
// The body carries the tokens — that is what separates push from ping — so these
// tests are about what leaves the process and under what conditions it refuses to.

func pushWorker(t *testing.T) (*Worker, *keys.RootKey) {
	t.Helper()
	w := testWorker(t)
	root, err := keys.NewRootKey("test-root", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.root = root
	w.client = &http.Client{}
	return w, root
}

func sealedResponse(t *testing.T, root *keys.RootKey, body map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := root.Seal(raw, store.SealContextCIBAPush)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// The happy path: the sealed token response is opened and delivered, with
// auth_req_id added as §10.3.1 requires.
func TestAPushDeliversTheTokensAndTheAuthReqID(t *testing.T) {
	w, root := pushWorker(t)

	var got map[string]any
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	w.client = srv.Client()

	err := w.deliverCIBAPush(context.Background(), store.CIBAPush{
		Endpoint:  srv.URL,
		Token:     "notification-token",
		AuthReqID: "areq-1",
		ClientID:  "c1",
		Sealed: sealedResponse(t, root, map[string]any{
			"access_token": "at-1", "token_type": "Bearer", "expires_in": 300,
		}),
	})
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}

	if got["access_token"] != "at-1" {
		t.Errorf("access_token = %v, want the sealed value", got["access_token"])
	}
	// §10.3.1: "a new parameter `auth_req_id` is included in the payload".
	if got["auth_req_id"] != "areq-1" {
		t.Errorf("auth_req_id = %v; without it the client cannot tell which of its "+
			"requests these tokens answer", got["auth_req_id"])
	}
	// §10.3.1: authenticated by the client's own notification token.
	if auth != "Bearer notification-token" {
		t.Errorf("Authorization = %q, want the client_notification_token", auth)
	}
}

// §9: the endpoint must be https. Checked at DELIVERY as well as at
// registration, because the row was parked earlier — one written by an older
// build or edited by hand must not put an access token on a plaintext connection.
func TestAPushRefusesAPlaintextEndpoint(t *testing.T) {
	w, root := pushWorker(t)

	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		reached = true
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := w.deliverCIBAPush(context.Background(), store.CIBAPush{
		Endpoint: srv.URL, // http://
		Token:    "t", AuthReqID: "a", ClientID: "c1",
		Sealed: sealedResponse(t, root, map[string]any{"access_token": "at-1"}),
	})
	if err == nil {
		t.Fatal("tokens were pushed to a plaintext endpoint")
	}
	if reached {
		t.Fatal("the request was actually sent before being refused")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("the refusal does not name the requirement: %v", err)
	}
}

// A row released with nothing sealed must fail loudly and not deliver an empty
// body to a client that will never ask again.
func TestAPushWithNoSealedTokensIsRefused(t *testing.T) {
	w, _ := pushWorker(t)
	err := w.deliverCIBAPush(context.Background(), store.CIBAPush{
		Endpoint: "https://rp.test/cb", Token: "t", AuthReqID: "a", ClientID: "c1",
	})
	if err == nil {
		t.Fatal("a push with no token response was delivered")
	}
	if !strings.Contains(err.Error(), "no token response") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The seal is bound to its purpose: a payload sealed for something else must not
// open here.
func TestAPayloadSealedForAnotherPurposeDoesNotOpen(t *testing.T) {
	w, root := pushWorker(t)

	raw, _ := json.Marshal(map[string]any{"access_token": "at-1"})
	wrong, err := root.Seal(raw, "some_other_context")
	if err != nil {
		t.Fatal(err)
	}
	derr := w.deliverCIBAPush(context.Background(), store.CIBAPush{
		Endpoint: "https://rp.test/cb", Token: "t", AuthReqID: "a", ClientID: "c1",
		Sealed: wrong,
	})
	if derr == nil {
		t.Fatal("a payload sealed for another purpose was delivered")
	}
}
