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
	_, _, err := ValidateExchange(req, true, nil, subj, caller, []string{"read"})
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
	granted, _, err := ValidateExchange(req, true, nil, subj, caller, []string{"read", "write"})
	if err != nil {
		t.Fatalf("narrowing was refused: %v", err)
	}
	if len(granted) != 1 || granted[0] != "read" {
		t.Errorf("granted %v, want [read]", granted)
	}

	// No scope requested inherits the subject's, unchanged.
	req.Scope = nil
	granted, _, err = ValidateExchange(req, true, nil, subj, caller, []string{"read", "write"})
	if err != nil || len(granted) != 2 {
		t.Errorf("granted %v err %v, want the subject's two scopes", granted, err)
	}
}

// Off by default: a client never granted exchange must not discover it by trying.
func TestExchangeIsRefusedUnlessGranted(t *testing.T) {
	req := ExchangeRequest{SubjectToken: "t", SubjectTokenType: TokenTypeAccess}
	_, _, err := ValidateExchange(req, false, nil, subj, caller, []string{"read"})
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
	if _, _, err := ValidateExchange(req, true, nil, subj, caller, []string{"read"}); err == nil {
		t.Fatal("a client with no configured audiences exchanged for an arbitrary one")
	}

	granted, aud, err := ValidateExchange(req, true,
		[]string{"https://payments.internal"}, subj, caller, []string{"read"})
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
	_, aud, err = ValidateExchange(req, true, nil, subj, caller, []string{"read"})
	if err != nil || len(aud) != 1 || aud[0] != caller {
		t.Errorf("aud %v err %v, want just the caller", aud, err)
	}
}

// Silently treating an ID token as an access token is how a token issued for
// AUTHENTICATION becomes one for AUTHORISATION.
func TestUnsupportedSubjectTokenTypesAreRefused(t *testing.T) {
	for _, tt := range []string{TokenTypeID, TokenTypeRefresh, "", "something-else"} {
		req := ExchangeRequest{SubjectToken: "t", SubjectTokenType: tt}
		if _, _, err := ValidateExchange(req, true, nil, subj, caller, []string{"read"}); err == nil {
			t.Errorf("subject_token_type %q was accepted", tt)
		}
	}
}
