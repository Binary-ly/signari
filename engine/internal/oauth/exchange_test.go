package oauth

import "testing"

const subj, caller = "svc-a", "svc-b"

// THE rule. Without it, exchange is privilege escalation with an RFC number:
// present a token with `read`, ask for `admin`, receive `admin`. The happy path
// works identically whether or not this check exists, which is exactly why it
// gets omitted.
func TestExchangeCannotAddScopes(t *testing.T) {
	req := ExchangeRequest{
		SubjectToken: "t", SubjectTokenType: TokenTypeAccess,
		Scope: []string{"read", "admin"},
	}
	_, _, err := ValidateExchange(req, true, true, nil, caller, []string{"read"})
	if err == nil {
		t.Fatal("an exchange ADDED a scope the subject token never had")
	}
	if err.Code != "invalid_scope" {
		t.Errorf("error code %q, want invalid_scope", err.Code)
	}
}

func TestExchangeMayNarrowScopes(t *testing.T) {
	req := ExchangeRequest{
		SubjectToken: "t", SubjectTokenType: TokenTypeAccess, Scope: []string{"read"},
	}
	granted, _, err := ValidateExchange(req, true, true, nil, caller, []string{"read", "write"})
	if err != nil {
		t.Fatalf("narrowing was refused: %v", err)
	}
	if len(granted) != 1 || granted[0] != "read" {
		t.Errorf("granted %v, want [read]", granted)
	}

	// No scope requested inherits the subject's, unchanged.
	req.Scope = nil
	granted, _, err = ValidateExchange(req, true, true, nil, caller, []string{"read", "write"})
	if err != nil || len(granted) != 2 {
		t.Errorf("granted %v err %v, want the subject's two scopes", granted, err)
	}
}

// Off by default: a client never granted exchange must not discover it by trying.
func TestExchangeIsRefusedUnlessGranted(t *testing.T) {
	req := ExchangeRequest{SubjectToken: "t", SubjectTokenType: TokenTypeAccess}
	_, _, err := ValidateExchange(req, true, false, nil, caller, []string{"read"})
	if err == nil || err.Code != "unauthorized_client" {
		t.Fatalf("exchange was allowed for a client without permission: %v", err)
	}
}

// An unrestricted exchanger can mint a token for any resource server in the
// deployment. The allow-list is what stops one compromised service reaching all
// the others.
func TestExchangeAudienceMustBeAllowed(t *testing.T) {
	req := ExchangeRequest{
		SubjectToken: "t", SubjectTokenType: TokenTypeAccess,
		Audience: []string{"https://payments.internal"},
	}
	if _, _, err := ValidateExchange(req, true, true, nil, caller, []string{"read"}); err == nil {
		t.Fatal("a client with no configured audiences exchanged for an arbitrary one")
	}

	granted, aud, err := ValidateExchange(req, true, true,
		[]string{"https://payments.internal"}, caller, []string{"read"})
	if err != nil {
		t.Fatalf("an explicitly allowed audience was refused: %v", err)
	}
	if len(aud) != 1 || aud[0] != "https://payments.internal" {
		t.Errorf("audience %v", aud)
	}
	_ = granted

	// With no audience requested, the token stays addressed to the caller --
	// the narrowest possible answer, never a wildcard.
	req.Audience = nil
	_, aud, err = ValidateExchange(req, true, true, nil, caller, []string{"read"})
	if err != nil || len(aud) != 1 || aud[0] != caller {
		t.Errorf("aud %v err %v, want just the caller", aud, err)
	}
}

// Silently treating an ID token as an access token is how a token issued for
// AUTHENTICATION becomes one for AUTHORISATION.
func TestUnsupportedSubjectTokenTypesAreRefused(t *testing.T) {
	for _, tt := range []string{TokenTypeID, TokenTypeRefresh, "", "something-else"} {
		req := ExchangeRequest{SubjectToken: "t", SubjectTokenType: tt}
		if _, _, err := ValidateExchange(req, true, true, nil, caller, []string{"read"}); err == nil {
			t.Errorf("subject_token_type %q was accepted", tt)
		}
	}
}

// RFC 8693 §2.1, on the server's obligations: "In processing the request, the
// authorization server MUST perform the appropriate validation procedures for
// the indicated token type and, if the actor token is present, also perform the
// appropriate validation procedures for its indicated token type."
//
// `actor_token` and `actor_token_type` were parsed into ExchangeRequest and read
// by nothing. A client sending an actor_token asserts "this specific party is
// doing the acting" -- and got a 200 with an `act` chain naming only the calling
// client, and no indication the assertion had been dropped.
//
// Not supporting delegated actors is a legitimate position. Proceeding as though
// the parameter had not been sent is not.
func TestAnActorTokenIsRefusedRatherThanIgnored(t *testing.T) {
	base := func() ExchangeRequest {
		return ExchangeRequest{
			SubjectToken:     "st",
			SubjectTokenType: TokenTypeAccess,
		}
	}

	t.Run("an actor token is refused", func(t *testing.T) {
		req := base()
		req.ActorToken = "at"
		req.ActorTokenType = TokenTypeAccess

		_, _, err := ValidateExchange(req, true, true, nil, "caller", []string{"read"})
		if err == nil {
			t.Fatal("an actor_token was accepted and silently ignored; the caller " +
				"believes it delegated through a specific actor and the issued " +
				"token does not say so")
		}
		if err.Code != "invalid_request" {
			t.Errorf("code = %q, want invalid_request", err.Code)
		}
	})

	t.Run("actor_token without its type", func(t *testing.T) {
		// §2.1: actor_token_type "is REQUIRED when the actor_token parameter is
		// present in the request".
		req := base()
		req.ActorToken = "at"

		_, _, err := ValidateExchange(req, true, true, nil, "caller", []string{"read"})
		if err == nil {
			t.Fatal("actor_token with no actor_token_type was accepted")
		}
	})

	t.Run("actor_token_type without the token", func(t *testing.T) {
		// §2.1: it "MUST NOT be included otherwise".
		req := base()
		req.ActorTokenType = TokenTypeAccess

		_, _, err := ValidateExchange(req, true, true, nil, "caller", []string{"read"})
		if err == nil {
			t.Fatal("actor_token_type was accepted without actor_token, which " +
				"§2.1 says MUST NOT be included")
		}
	})

	t.Run("neither is the ordinary case", func(t *testing.T) {
		if _, _, err := ValidateExchange(base(), true, true, nil, "caller", []string{"read"}); err != nil {
			t.Fatalf("an ordinary exchange with no actor token was refused: %v", err)
		}
	})
}
