package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// §7.1: "client_notification_token REQUIRED if the Client is registered to use
// Ping or Push modes."
//
// Both directions are errors, and the second is the one an implementation adding
// ping tends to lose: once the parameter is accepted for ping clients, it is easy
// to stop refusing it for poll clients, and a poll client that sends one has
// misunderstood which mode it is in.
func TestTheNotificationTokenIsRequiredForPingAndRefusedForPoll(t *testing.T) {
	base := func() url.Values {
		return url.Values{
			"scope":      {"openid"},
			"login_hint": {"someone@example.test"},
		}
	}

	// Ping, no token: refused.
	f := base()
	if _, err := ParseCIBARequest(f, "client-1", DeliveryPing); err == nil {
		t.Error("a ping client with no client_notification_token was accepted; the " +
			"notification could be delivered but not authenticated to the client")
	} else if !strings.Contains(err.Description, "client_notification_token is required") {
		t.Errorf("refused, but not for the missing token: %s", err.Description)
	}

	// Ping, with a token: accepted.
	f = base()
	f.Set("client_notification_token", "8d1f4c9a2b7e5063f1a8c4d92e7b0356")
	if _, err := ParseCIBARequest(f, "client-1", DeliveryPing); err != nil {
		t.Errorf("a conformant ping request was refused: %s", err.Description)
	}

	// Poll, with a token: still refused.
	f = base()
	f.Set("client_notification_token", "8d1f4c9a2b7e5063f1a8c4d92e7b0356")
	if _, err := ParseCIBARequest(f, "client-1", DeliveryPoll); err == nil {
		t.Error("a poll client sent a client_notification_token and was accepted; " +
			"no notification will ever be sent, so the client is waiting for " +
			"something that cannot arrive")
	}

	// Poll, no token: accepted, which is the ordinary case and must not regress.
	f = base()
	if _, err := ParseCIBARequest(f, "client-1", DeliveryPoll); err != nil {
		t.Errorf("an ordinary poll request was refused: %s", err.Description)
	}
}

// §7.1's two limits that are ours to enforce.
//
// "The length of the token MUST NOT exceed 1024 characters and it MUST conform to
// the syntax for Bearer credentials as defined in Section 2.1 of [RFC6750]."
//
// The third requirement in that paragraph — a minimum of 128 bits of entropy — is
// explicitly an obligation on the *Client*, and is deliberately not checked: a
// 128-bit random value and a padded English word are the same string to a
// verifier, so any proxy for entropy would refuse conformant clients using a
// compact encoding while still accepting a long guessable token.
func TestTheNotificationTokenIsBoundedAndWellFormed(t *testing.T) {
	req := func(tok string) *CIBAError {
		f := url.Values{
			"scope": {"openid"}, "login_hint": {"someone@example.test"},
			"client_notification_token": {tok},
		}
		_, err := ParseCIBARequest(f, "client-1", DeliveryPing)
		return err
	}

	if err := req(strings.Repeat("a", maxClientNotificationToken)); err != nil {
		t.Errorf("a token of exactly %d characters was refused: %s",
			maxClientNotificationToken, err.Description)
	}
	if err := req(strings.Repeat("a", maxClientNotificationToken+1)); err == nil {
		t.Errorf("a token of %d characters was accepted; §7.1 permits at most %d",
			maxClientNotificationToken+1, maxClientNotificationToken)
	}

	// RFC 6750 §2.1 b64token: ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/"
	// with optional "=" padding. Everything else is not a bearer credential, and
	// a space or a control character would let a token span a header boundary.
	for _, bad := range []string{
		"has a space", "has\ttab", "has\nnewline", "quote\"inside",
		"semi;colon", "back\\slash", "", "====",
	} {
		if err := req(bad); err == nil {
			t.Errorf("token %q was accepted; RFC 6750 §2.1 does not permit it", bad)
		}
	}
	for _, ok := range []string{
		"abcDEF123", "with-dash", "with.dot", "with_underscore",
		"with~tilde", "with+plus", "with/slash", "padded==",
	} {
		if err := req(ok); err != nil {
			t.Errorf("token %q is valid b64token and was refused: %s", ok, err.Description)
		}
	}
}
