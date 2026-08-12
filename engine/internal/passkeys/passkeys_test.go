package passkeys

import (
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// An instance with no rp_id must refuse to build a relying party rather than
// guess. Guessing produces credentials bound to a value nobody chose, and the
// value is permanent once a passkey exists.
func TestMissingRPIDIsRefused(t *testing.T) {
	if _, err := New("", "Signari", "https://id.example.com"); err == nil {
		t.Fatal("a relying party was built with no rp_id")
	}
}

// Every one of these produces a browser ceremony that fails with a message
// naming neither the parameter nor the cause, so they are refused here where the
// error can say what is actually wrong.
func TestMalformedRPIDIsRefused(t *testing.T) {
	for _, bad := range []string{
		"https://example.com", // scheme
		"example.com:8443",    // port
		"example.com/auth",    // path
		"http://localhost",    // scheme again, the most common mistake
	} {
		if _, err := New(bad, "Signari", "https://example.com"); err == nil {
			t.Errorf("rp_id %q was accepted", bad)
		}
	}
}

// The origin list is DERIVED from the rp_id, never configured separately.
// Configuring both independently is how a deployment ends up with an rp_id and
// an origin list that disagree.
func TestOriginsAreDerivedFromTheRPID(t *testing.T) {
	// The normal production shape: registrable domain, IdP on a subdomain.
	got := originsFor("example.com", "https://id.example.com")
	if !contains(got, "https://example.com") {
		t.Errorf("the rp_id origin is missing: %v", got)
	}
	if !contains(got, "https://id.example.com") {
		t.Errorf("the issuer's own origin is missing, so the IdP cannot run a ceremony: %v", got)
	}

	// An issuer that is NOT under the rp_id must not be added. Doing so would
	// let a ceremony from an unrelated origin use these credentials.
	got = originsFor("example.com", "https://evil.test")
	if contains(got, "https://evil.test") {
		t.Errorf("an unrelated issuer origin was trusted: %v", got)
	}

	// A near-miss suffix must not match either: "notexample.com" ends with
	// "example.com" as a string but is a different registrable domain.
	got = originsFor("example.com", "https://notexample.com")
	if contains(got, "https://notexample.com") {
		t.Errorf("a suffix look-alike domain was trusted: %v", got)
	}
}

// localhost is the only host where passkeys work without TLS, because browsers
// treat it as a secure context. Every other host must be https only.
func TestLocalhostGetsPlaintextAndNothingElseDoes(t *testing.T) {
	got := originsFor("localhost", "http://localhost:9411")
	if !contains(got, "http://localhost") {
		t.Errorf("localhost did not get a plaintext origin, so local development cannot work: %v", got)
	}

	got = originsFor("example.com", "http://example.com")
	for _, o := range got {
		if strings.HasPrefix(o, "http://") {
			t.Errorf("a non-localhost host was given a plaintext origin: %v", got)
		}
	}
}

// Registration policy: resident keys and user verification are both REQUIRED.
//
// Without resident keys there is no conditional UI, so the user must type an
// identifier before the browser offers their passkey -- removing most of the
// point. Without user verification a passkey proves possession of a device and
// nothing more, so it is one factor and cannot honestly back an acr of 2.
func TestRegistrationRequiresResidentKeyAndUserVerification(t *testing.T) {
	rp, err := New("localhost", "Signari", "http://localhost:9411")
	if err != nil {
		t.Fatal(err)
	}
	u := &User{ID: make([]byte, 64), Name: "alice@example.test", DisplayName: "Alice"}

	creation, session, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	sel := creation.Response.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want required -- conditional UI will not work", sel.ResidentKey)
	}
	if sel.UserVerification != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want required -- this would be one factor, not two", sel.UserVerification)
	}
	if len(session.Challenge) == 0 {
		t.Error("no challenge was issued")
	}
	if creation.Response.RelyingParty.ID != "localhost" {
		t.Errorf("rp id in the ceremony = %q, want localhost", creation.Response.RelyingParty.ID)
	}
}

// Re-registering the SAME authenticator must be excluded, or one device produces
// two credential rows and silently satisfies the two-credential rule on its own.
func TestExistingCredentialsAreExcluded(t *testing.T) {
	rp, _ := New("localhost", "Signari", "http://localhost:9411")
	u := &User{ID: make([]byte, 64), Name: "alice", DisplayName: "Alice"}

	creation, _, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(creation.Response.CredentialExcludeList) != 0 {
		t.Errorf("a user with no credentials produced an exclude list: %v", creation.Response.CredentialExcludeList)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
