package uma

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// A single object and an array are both a permission request, and the values
// are trimmed before anything is checked against them.
func TestAPermissionRequestIsOneObjectOrAnArray(t *testing.T) {
	one, perr := ParsePermissions([]byte(`  {"resource_type":" document ","resource_id":" 42 ","resource_scopes":["read"]}  `))
	if perr != nil {
		t.Fatalf("a single object was refused: %v", perr)
	}
	if len(one) != 1 || one[0].ResourceType != "document" || one[0].ResourceID != "42" {
		t.Fatalf("a single object parsed as %+v", one)
	}

	many, perr := ParsePermissions([]byte(`[
		{"resource_type":"document","resource_id":"42","resource_scopes":["read"]},
		{"resource_type":"invoice","resource_id":"42","resource_scopes":["read","pay"]}]`))
	if perr != nil {
		t.Fatalf("an array was refused: %v", perr)
	}
	if len(many) != 2 || many[1].ResourceType != "invoice" || len(many[1].ResourceScopes) != 2 {
		t.Fatalf("an array parsed as %+v", many)
	}
}

// Every refusal is invalid_request with a 400, and each says which rule it
// broke rather than that the body was bad.
func TestAPermissionThatIsNotAQuestionIsRefused(t *testing.T) {
	var tooMany []string
	for i := 0; i <= MaxPermissions; i++ {
		tooMany = append(tooMany, fmt.Sprintf(`{"resource_type":"document","resource_id":"%d","resource_scopes":["read"]}`, i))
	}
	for _, c := range []struct {
		name, body, says string
	}{
		{"no body", "   ", "no body"},
		{"not JSON", `resource=42`, "neither"},
		{"an empty array", `[]`, "names no resources"},
		{"too many", "[" + strings.Join(tooMany, ",") + "]", fmt.Sprintf("at most %d", MaxPermissions)},
		{"no resource_id", `{"resource_type":"document","resource_scopes":["read"]}`, "resource_id"},
		{"a blank resource_id", `{"resource_type":"document","resource_id":"  ","resource_scopes":["read"]}`, "resource_id"},
		{"no resource_type", `{"resource_id":"42","resource_scopes":["read"]}`, "resource_type"},
		{"no scopes", `{"resource_type":"document","resource_id":"42","resource_scopes":[]}`, "at least one"},
		{"a blank scope", `{"resource_type":"document","resource_id":"42","resource_scopes":["read"," "]}`, "may not be empty"},
		// One bad entry refuses the whole request, wherever it sits.
		{"a bad second entry", `[{"resource_type":"document","resource_id":"1","resource_scopes":["read"]},
			{"resource_id":"2","resource_scopes":["read"]}]`, "resource_type"},
	} {
		got, perr := ParsePermissions([]byte(c.body))
		if perr == nil {
			t.Errorf("%s: accepted as %+v", c.name, got)
			continue
		}
		if perr.Code != "invalid_request" || perr.Status != http.StatusBadRequest {
			t.Errorf("%s: refused as %s %d, want invalid_request 400", c.name, perr.Code, perr.Status)
		}
		if !strings.Contains(perr.Description, c.says) {
			t.Errorf("%s: the refusal %q does not say %q", c.name, perr.Description, c.says)
		}
	}

	exactly := make([]string, MaxPermissions)
	copy(exactly, tooMany)
	if _, perr := ParsePermissions([]byte("[" + strings.Join(exactly, ",") + "]")); perr != nil {
		t.Errorf("exactly %d permissions were refused: %v", MaxPermissions, perr)
	}
}

// The RPT's scope keeps the resource as well as the verb, so "read" on
// document 42 and "read" on invoice 42 are different scopes, and asking twice
// for the same thing grants it once.
func TestAnRPTScopeNamesTheResourceAndTheVerb(t *testing.T) {
	got := Scopes([]Permission{
		{ResourceType: "document", ResourceID: "42", ResourceScopes: []string{"read", "write"}},
		{ResourceType: "invoice", ResourceID: "42", ResourceScopes: []string{"read"}},
		{ResourceType: "document", ResourceID: "42", ResourceScopes: []string{"read"}},
	})
	want := []string{"document:42#read", "document:42#write", "invoice:42#read"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("scopes are %q, want %q", got, want)
	}
	if Scopes(nil) != nil {
		t.Errorf("no permissions produced scopes")
	}
}

// A ticket is as wide as an authorization code, URL-safe, and never repeats.
func TestATicketIsThirtyTwoUnrepeatedBytes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		ticket, err := NewTicket()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(ticket)
		if err != nil || len(raw) != 32 {
			t.Fatalf("ticket %q is not 32 base64url bytes (%d, %v)", ticket, len(raw), err)
		}
		if seen[ticket] {
			t.Fatalf("ticket %q was issued twice", ticket)
		}
		seen[ticket] = true
	}
}

// A claim_token is a compact JWT, either raw or base64url-encoded, and the two
// spellings cannot be confused because base64url has no dot.
func TestAClaimTokenIsAJWTInEitherSpelling(t *testing.T) {
	const jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"
	for _, c := range []struct{ name, in string }{
		{"raw", jwt},
		{"raw, padded with space", "  " + jwt + "\n"},
		{"base64url", base64.RawURLEncoding.EncodeToString([]byte(jwt))},
		{"base64url with padding", base64.URLEncoding.EncodeToString([]byte(jwt + "x"))},
	} {
		got, err := DecodeClaimToken(c.in)
		if err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
			continue
		}
		if c.name == "base64url with padding" {
			if got != jwt+"x" {
				t.Errorf("%s: decoded to %q", c.name, got)
			}
		} else if got != jwt {
			t.Errorf("%s: decoded to %q", c.name, got)
		}
	}

	for _, c := range []struct{ name, in, says string }{
		{"empty", "  ", "empty"},
		{"not base64url", "not*base64", "does not decode"},
		// Valid base64url of something that is not a JWT is still not a JWT.
		// Only the shape is checked here; the signature check that follows is
		// what refuses a dotted string that is not a token.
		{"base64url of a non-JWT", base64.RawURLEncoding.EncodeToString([]byte("alice")), "not a compact JWT"},
	} {
		if got, err := DecodeClaimToken(c.in); err == nil {
			t.Errorf("%s: accepted as %q", c.name, got)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the refusal %q does not say %q", c.name, err, c.says)
		}
	}
}

// §3.3.6 gives need_info, request_denied and request_submitted 403 and
// invalid_grant 400; need_info carries a ticket and both hints, and
// request_submitted carries the next ticket.
func TestEachUMAErrorHasTheStatusAndHintsTheSpecificationGivesIt(t *testing.T) {
	need := NeedInfo("t1", "https://idp.test/uma2/claims", []RequiredClaim{SubjectClaim("https://idp.test")}, "who are you")
	if need.Code != "need_info" || need.Status != http.StatusForbidden || need.Ticket != "t1" ||
		need.RedirectUser == "" || len(need.RequiredClaims) != 1 {
		t.Errorf("need_info is %+v", need)
	}
	sub := Submitted("t2", 5, "waiting for the owner")
	if sub.Code != "request_submitted" || sub.Status != http.StatusForbidden || sub.Ticket != "t2" || sub.Interval != 5 {
		t.Errorf("request_submitted is %+v", sub)
	}
	if d := Denied("no"); d.Code != "request_denied" || d.Status != http.StatusForbidden {
		t.Errorf("request_denied is %+v", d)
	}
	if g := InvalidGrant("spent"); g.Code != "invalid_grant" || g.Status != http.StatusBadRequest {
		t.Errorf("invalid_grant is %+v", g)
	}
	if e := Denied("policy said no"); e.Error() != "request_denied: policy said no" {
		t.Errorf("Error() is %q", e.Error())
	}

	// The required claim names this server as the only issuer, and the ID
	// token as the only format, so a client knows exactly what to fetch.
	c := SubjectClaim("https://idp.test")
	if len(c.Issuer) != 1 || c.Issuer[0] != "https://idp.test" ||
		len(c.ClaimTokenFormat) != 1 || c.ClaimTokenFormat[0] != ClaimTokenFormatIDToken ||
		c.Name == "" || c.ClaimType == "" || c.FriendlyName == "" {
		t.Errorf("the subject claim is %+v", c)
	}
}
