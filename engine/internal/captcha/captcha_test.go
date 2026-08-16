package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ctx is shared by these tests: none of them exercises cancellation, and
// threading a fresh one through every call would be noise.
var ctx = context.Background()

func TestOffByDefault(t *testing.T) {
	var v *Verifier
	if v.Enabled() {
		t.Error("a nil verifier reports enabled")
	}
	// Every method must tolerate a nil receiver, so a deployment with no CAPTCHA
	// needs no branches at the call sites.
	if v.Required(ctx, "1.2.3.4:1234") {
		t.Error("a nil verifier required a challenge")
	}
	v.RecordFailure(ctx, "1.2.3.4:1234")
	v.Clear(ctx, "1.2.3.4:1234")
	// These two were NOT nil-safe and panicked on the sign-in page of every
	// deployment without a CAPTCHA. The login renderer reads them on every
	// request, so "the caller checks first" was never going to hold.
	if v.SiteKey() != "" {
		t.Error("a nil verifier returned a site key")
	}
	if v.Provider() != "" {
		t.Error("a nil verifier returned a provider")
	}
	if err := v.Verify(context.Background(), "", "1.2.3.4:1234"); err != nil {
		t.Errorf("a nil verifier refused: %v", err)
	}

	empty := New(Config{}, nil)
	if empty.Enabled() {
		t.Error("an unconfigured verifier reports enabled")
	}
}

// TestAdaptiveOnlyChallengesAfterFailures. The point of adaptive mode: somebody
// signing in normally never sees a challenge.
func TestAdaptiveOnlyChallengesAfterFailures(t *testing.T) {
	v := New(Config{Mode: ModeAdaptive, Provider: Turnstile, Secret: "s",
		FailuresBeforeChallenge: 3}, nil)
	const addr = "203.0.113.7:5555"

	if v.Required(ctx, addr) {
		t.Fatal("a challenge was required before any failure")
	}
	v.RecordFailure(ctx, addr)
	v.RecordFailure(ctx, addr)
	if v.Required(ctx, addr) {
		t.Error("challenged after 2 failures with a threshold of 3")
	}
	v.RecordFailure(ctx, addr)
	if !v.Required(ctx, addr) {
		t.Error("not challenged after reaching the threshold")
	}

	// A different address is unaffected: pressure is per source, not global.
	if v.Required(ctx, "198.51.100.9:1111") {
		t.Error("one address's failures challenged a different address")
	}

	// Success clears it, so the next person on an office NAT does not inherit a
	// challenge from somebody who mistyped.
	v.Clear(ctx, addr)
	if v.Required(ctx, addr) {
		t.Error("a challenge survived a successful sign-in")
	}
}

func TestAlwaysChallenges(t *testing.T) {
	v := New(Config{Mode: ModeAlways, Provider: Turnstile, Secret: "s"}, nil)
	if !v.Required(ctx, "203.0.113.7:1") {
		t.Error("always mode did not require a challenge")
	}
}

func TestVerifyAcceptsAndRejects(t *testing.T) {
	var gotSecret, gotResponse string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.PostForm.Get("secret")
		gotResponse = r.PostForm.Get("response")
		if gotResponse == "good" {
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer srv.Close()

	verifyURLs[Turnstile] = srv.URL
	t.Cleanup(func() {
		verifyURLs[Turnstile] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	})

	v := New(Config{Mode: ModeAlways, Provider: Turnstile, Secret: "the-secret"}, srv.Client())

	if err := v.Verify(context.Background(), "good", "203.0.113.1:1"); err != nil {
		t.Fatalf("a solved challenge was refused: %v", err)
	}
	if gotSecret != "the-secret" {
		t.Errorf("the secret was not sent: %q", gotSecret)
	}
	if err := v.Verify(context.Background(), "bad", "203.0.113.1:1"); err == nil {
		t.Error("an unsolved challenge was accepted")
	}
	// An empty response must never reach the provider: it cannot be valid, and
	// sending it spends a round trip on every blank form submission.
	if err := v.Verify(context.Background(), "", "203.0.113.1:1"); err == nil {
		t.Error("an empty response was accepted")
	}
}

// TestUnreachableProviderFailsOpenByDefault.
//
// This check sits IN FRONT of a password, not instead of one. Failing open
// degrades to the posture of having no CAPTCHA; failing closed turns somebody
// else's outage into a total authentication outage.
func TestUnreachableProviderFailsOpenByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // refuse connections

	verifyURLs[Turnstile] = srv.URL
	t.Cleanup(func() {
		verifyURLs[Turnstile] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	})

	open := New(Config{Mode: ModeAlways, Provider: Turnstile, Secret: "s"}, srv.Client())
	if err := open.Verify(context.Background(), "anything", "203.0.113.1:1"); err != nil {
		t.Errorf("an unreachable provider blocked a sign-in by default: %v", err)
	}

	closed := New(Config{Mode: ModeAlways, Provider: Turnstile, Secret: "s",
		FailClosed: true}, srv.Client())
	if err := closed.Verify(context.Background(), "anything", "203.0.113.1:1"); err == nil {
		t.Error("FailClosed did not block when the provider was unreachable")
	}
}

// TestUnknownConfigurationIsRefused. A typo must not silently disable a control
// the operator believes they configured.
func TestUnknownConfigurationIsRefused(t *testing.T) {
	if _, err := ParseMode("adaptative"); err == nil {
		t.Error("a misspelled mode was accepted")
	}
	if _, err := ParseProvider("hcapcha"); err == nil {
		t.Error("a misspelled provider was accepted")
	}
	// Empty means off, which is the documented default rather than a typo.
	if m, err := ParseMode(""); err != nil || m != ModeOff {
		t.Errorf("empty mode = %q, %v; want off", m, err)
	}
}
