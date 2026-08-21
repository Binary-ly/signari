package outbox

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A `backchannel_logout_uri` is chosen by the CLIENT, at registration. A webhook
// subscription is chosen by an OPERATOR.
//
// Webhook delivery has gone through `safedial` since it was written — checked at
// save time and again in the dialler. Back-channel logout delivery used a plain
// `http.Client`, so the LESS trusted of the two destinations had no address check
// at all: a client registering `http://169.254.169.254/…` would have had a signed
// logout token POSTed there on every sign-out by one of its users.
//
// Found by asking which outbound clients in the engine use safedial, after three
// separate findings that week turned out to be the same shape: a rule enforced in
// fewer places than its own documentation claimed.

func TestLogoutDeliveryRefusesPrivateAddresses(t *testing.T) {
	// A real listener on loopback, so this tests the dialler rather than a
	// parsing rule: the address is genuinely reachable and must still be refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var reached bool
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	t.Setenv(AllowPrivateDelivery, "")

	c := outboundClient(5 * time.Second)
	resp, err := c.Post("http://"+ln.Addr().String()+"/logout", "application/jwt",
		strings.NewReader("signed.logout.token"))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a logout token was delivered to %s; a client that registers a "+
			"private backchannel_logout_uri would have this server POST a signed "+
			"token into the internal network on every sign-out", ln.Addr())
	}
	if reached {
		t.Error("the request reached the loopback listener")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Errorf("refused, but not by the address check: %v", err)
	}
}

// The escape hatch must work, or deployments whose relying parties are genuinely
// internal cannot deliver logout at all — which is why this was unguarded.
func TestPrivateDeliveryCanBeAllowedExplicitly(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	t.Setenv(AllowPrivateDelivery, "1")

	c := outboundClient(5 * time.Second)
	resp, err := c.Post(target.URL, "application/jwt", strings.NewReader("t"))
	if err != nil {
		t.Fatalf("delivery was refused with the opt-out set: %v", err)
	}
	_ = resp.Body.Close()
}

// Trusting an internal certificate authority and permitting requests into the
// private network are different decisions. Setting a CA bundle must not quietly
// grant the second.
func TestACABundleDoesNotImplyPrivateDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	t.Setenv(AllowPrivateDelivery, "")
	t.Setenv("SIGNARI_CA_BUNDLE", "/nonexistent/ca.pem")

	c := outboundClient(2 * time.Second)
	if _, err := c.Post("http://"+ln.Addr().String()+"/x", "application/jwt",
		strings.NewReader("t")); err == nil {
		t.Error("setting a CA bundle allowed delivery to a private address")
	}
}
