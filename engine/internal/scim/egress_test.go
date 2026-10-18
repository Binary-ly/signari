package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A client built without one of its own refuses a target on a private address
// before the bearer token is sent: that token can create and delete accounts,
// and the base URL is a stored setting.
func TestTheDefaultClientDoesNotSendTheTokenIntoThePrivateNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the target on loopback was sent %q", r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	c := NewClient(Target{BaseURL: srv.URL, Token: "t"}, nil)
	_, err := c.GetUser(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("err = %v, want the dialler's refusal", err)
	}
}
