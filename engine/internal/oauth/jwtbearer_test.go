package oauth

import (
	"encoding/json"
	"testing"
	"time"
)

// RFC 7523 §3, item by item, plus §3.1.
//
// Every rejection here is a MUST in the specification. They are tested
// individually rather than through one "valid assertion" case because a claim
// check that is missing does not fail loudly -- it accepts something, and the
// only way to know is to present the thing it should have refused.

var ourIssuers = []string{"https://idp.example.com", "https://legacy.example.com"}

func goodAssertion(now time.Time) AssertionClaims {
	return AssertionClaims{
		Issuer:   "https://platform.example",
		Subject:  "workload-7",
		Audience: Audience{"https://idp.example.com"},
		Expiry:   now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(),
		JTI:      "a1",
	}
}

func TestAConformantAssertionIsAccepted(t *testing.T) {
	now := time.Now()
	if err := ValidateAssertionClaims(goodAssertion(now), ourIssuers, now); err != nil {
		t.Fatalf("a valid assertion was refused: %s", err.Description)
	}
}

func TestEachRequiredClaimIsEnforced(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		fn   func(*AssertionClaims)
		want string
	}{
		{"§3 item 1: no iss", func(c *AssertionClaims) { c.Issuer = "" }, "iss"},
		{"§3 item 2: no sub", func(c *AssertionClaims) { c.Subject = "" }, "sub"},
		{"§3 item 3: no aud", func(c *AssertionClaims) { c.Audience = nil }, "aud"},
		{"§3 item 4: no exp", func(c *AssertionClaims) { c.Expiry = 0 }, "exp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := goodAssertion(now)
			tc.fn(&c)
			err := ValidateAssertionClaims(c, ourIssuers, now)
			if err == nil {
				t.Fatalf("accepted an assertion with no %s", tc.want)
			}
			if err.Code != "invalid_grant" {
				t.Errorf("error code = %q, want invalid_grant", err.Code)
			}
		})
	}
}

// §3.1: "The authorization server MUST reject any JWT that does not contain its
// own identity as the intended audience."
//
// This is the rule that stops an assertion minted for another relying party being
// forwarded here. Its absence is invisible in every working deployment.
func TestAnAssertionForSomebodyElseIsRefused(t *testing.T) {
	now := time.Now()
	c := goodAssertion(now)
	c.Audience = Audience{"https://someone-else.example"}
	if err := ValidateAssertionClaims(c, ourIssuers, now); err == nil {
		t.Fatal("accepted an assertion whose audience names a different relying party")
	}

	// A registered alias still names us, because the rest of the engine accepts
	// those as our identity too.
	c.Audience = Audience{"https://legacy.example.com"}
	if err := ValidateAssertionClaims(c, ourIssuers, now); err != nil {
		t.Errorf("a registered issuer alias was not accepted as our identity: %s", err.Description)
	}

	// And one of several audiences naming us is enough: an assertion may legally
	// address several parties.
	c.Audience = Audience{"https://other.example", "https://idp.example.com"}
	if err := ValidateAssertionClaims(c, ourIssuers, now); err != nil {
		t.Errorf("an assertion naming us among several audiences was refused: %s", err.Description)
	}
}

// An empty configured issuer must never match an empty audience entry. This is
// the audience check switching itself off on a configuration mistake.
func TestAnEmptyIssuerIsNotAnIdentity(t *testing.T) {
	now := time.Now()
	c := goodAssertion(now)
	c.Audience = Audience{""}
	if err := ValidateAssertionClaims(c, []string{"", "https://idp.example.com"}, now); err == nil {
		t.Fatal("an empty audience matched an empty configured issuer")
	}
}

// §3 item 4 again: "The authorization server MUST reject JWTs with an `exp`
// claim value that is unreasonably far in the future."
//
// An assertion valid for a year is a bearer credential valid for a year, whatever
// the issuer meant by it.
func TestAnAssertionValidTooLongIsRefused(t *testing.T) {
	now := time.Now()
	c := goodAssertion(now)
	c.Expiry = now.Add(MaxAssertionLifetime + time.Minute).Unix()
	if err := ValidateAssertionClaims(c, ourIssuers, now); err == nil {
		t.Fatalf("accepted an assertion valid for more than %s", MaxAssertionLifetime)
	}

	// The boundary itself is fine.
	c.Expiry = now.Add(MaxAssertionLifetime - time.Second).Unix()
	if err := ValidateAssertionClaims(c, ourIssuers, now); err != nil {
		t.Errorf("an assertion just inside the ceiling was refused: %s", err.Description)
	}
}

func TestExpiredAndNotYetValidAssertionsAreRefused(t *testing.T) {
	now := time.Now()

	expired := goodAssertion(now)
	expired.Expiry = now.Add(-2 * AssertionSkew).Unix()
	if err := ValidateAssertionClaims(expired, ourIssuers, now); err == nil {
		t.Error("accepted an expired assertion")
	}

	// §3 item 5: nbf is optional, and binding when present.
	future := goodAssertion(now)
	future.NotBefore = now.Add(10 * time.Minute).Unix()
	if err := ValidateAssertionClaims(future, ourIssuers, now); err == nil {
		t.Error("accepted an assertion before its nbf")
	}

	// §3 item 6: an iat in the future is a clock fault or a forgery.
	ahead := goodAssertion(now)
	ahead.IssuedAt = now.Add(10 * time.Minute).Unix()
	if err := ValidateAssertionClaims(ahead, ourIssuers, now); err == nil {
		t.Error("accepted an assertion issued in the future")
	}
}

// nbf and iat are MAY. Refusing an assertion that omits them would reject
// conformant issuers.
func TestOptionalClaimsMayBeAbsent(t *testing.T) {
	now := time.Now()
	c := goodAssertion(now)
	c.NotBefore, c.IssuedAt, c.JTI = 0, 0, ""
	if err := ValidateAssertionClaims(c, ourIssuers, now); err != nil {
		t.Fatalf("an assertion without the optional claims was refused: %s", err.Description)
	}
}

// RFC 7519 §4.1.3 allows both spellings, and a real issuer will use each.
func TestBothAudienceSpellingsDecode(t *testing.T) {
	for _, raw := range []string{
		`{"aud":"https://idp.example.com"}`,
		`{"aud":["https://idp.example.com"]}`,
		`{"aud":["https://a.example","https://idp.example.com"]}`,
	} {
		var c AssertionClaims
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("%s did not decode: %v", raw, err)
		}
		if !audienceNamesUs(c.Audience, ourIssuers) {
			t.Errorf("%s decoded but did not name us: %v", raw, c.Audience)
		}
	}
	// And something that is neither must be an error, not a silent empty.
	var c AssertionClaims
	if err := json.Unmarshal([]byte(`{"aud":42}`), &c); err == nil {
		t.Error("a numeric aud decoded without complaint")
	}
}
