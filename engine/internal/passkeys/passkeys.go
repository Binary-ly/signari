// Package passkeys wraps go-webauthn with this server's own rules.
//
// The library handles the cryptography and the protocol correctly; what it
// cannot decide for us is policy. This package is where that policy lives, so
// there is one place to read it rather than a dozen call sites that each
// remembered a different subset:
//
//   - which RP ID and origins this instance uses (per instance, never global)
//   - what a user's credential list is, and where it comes from
//   - what happens when the signature counter says "cloned"
//   - whether a user may drop their password (never on one credential)
package passkeys

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"signari.dev/engine/internal/store"
)

// Relying is one instance's WebAuthn configuration.
type Relying struct {
	w    *webauthn.WebAuthn
	rpID string
}

// New builds the relying party for an instance.
//
// The origins are derived from the RP ID rather than configured separately.
// Configuring them independently is how a deployment ends up with an RP ID and
// an origin list that disagree -- a ceremony that fails in the browser with a
// message naming neither.
func New(rpID, displayName string, issuer string) (*Relying, error) {
	if rpID == "" {
		return nil, fmt.Errorf("passkeys: this instance has no rp_id set; passkeys are unavailable until it is")
	}
	if strings.Contains(rpID, "://") || strings.Contains(rpID, ":") || strings.Contains(rpID, "/") {
		return nil, fmt.Errorf("passkeys: rp_id %q must be a bare domain, with no scheme, port or path", rpID)
	}
	// An IP address is not a valid RP ID. The spec requires a domain, and Chrome
	// refuses the ceremony outright -- so a deployment reached over an IP cannot
	// use passkeys at all, and saying so here beats an opaque browser failure.
	if net.ParseIP(rpID) != nil {
		return nil, fmt.Errorf("passkeys: rp_id %q is an IP address; WebAuthn requires a domain "+
			"(use localhost for development)", rpID)
	}
	if displayName == "" {
		displayName = rpID
	}

	origins := originsFor(rpID, issuer)
	w, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &Relying{w: w, rpID: rpID}, nil
}

// RPID is the value credentials will be bound to. Exposed so callers can record
// it with each credential rather than re-deriving it later.
func (r *Relying) RPID() string { return r.rpID }

// originsFor lists the origins a ceremony may legitimately come from.
//
// https://<rpID> always, plus the issuer's own origin when it is a subdomain of
// the RP ID -- which is the normal deployment (rp_id example.com, issuer
// https://id.example.com). localhost additionally gets http, because browsers
// treat it as a secure context and it is the only place passkeys work without
// TLS.
// An origin is scheme://host:port. THE PORT IS PART OF IT -- a browser at
// http://localhost:9411 does not match an origin of http://localhost, and the
// ceremony fails with "Error validating origin", which names neither the port
// nor the parameter. This is the single most common WebAuthn misconfiguration
// and it cost this implementation a real bug that unit tests did not catch.
func originsFor(rpID, issuer string) []string {
	origins := []string{"https://" + rpID}

	if rpID == "localhost" {
		origins = append(origins, "http://localhost")
	}
	if u, err := url.Parse(issuer); err == nil && u.Host != "" {
		host := u.Hostname()
		// A suffix match is not a domain match: "notexample.com" ends with
		// "example.com" as a string but is a different registrable domain, and
		// trusting it would hand credentials to whoever owns it.
		underRPID := host == rpID || strings.HasSuffix(host, "."+rpID)

		// http is only ever acceptable on localhost, which browsers treat as a
		// secure context. Advertising a plaintext origin for any other host says
		// a ceremony over an interceptable connection is fine, and it is not --
		// even though the browser would refuse it anyway, the server must not be
		// the one claiming otherwise.
		secure := u.Scheme == "https" || host == "localhost" || host == "127.0.0.1"

		if underRPID && secure {
			// u.Host, NOT u.Hostname(): Host keeps the port, and the port is part
			// of the origin the browser will send.
			if o := u.Scheme + "://" + u.Host; !contains(origins, o) {
				origins = append(origins, o)
			}
		}
	}
	return origins
}

// User adapts a stored user and their credentials to the library's interface.
//
// Built per ceremony from the database rather than cached: a credential deleted
// on another device must not still be offered here, and a stale list is how a
// revoked authenticator keeps working.
type User struct {
	ID          []byte // the 64-byte user_handle, NOT the uuid
	Name        string
	DisplayName string
	Creds       []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

// ToLibrary converts stored credentials into the library's shape.
func ToLibrary(stored []store.WebAuthnCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			AttestationType: func() string {
				return "none"
			}(),
			Transport: transports,
			// BackupEligible MUST come from what registration recorded.
			//
			// WebAuthn L3 §6.1.3 fixes BE at registration and forbids it changing,
			// and go-webauthn enforces that by comparing the asserted flag against
			// the one on this struct. It used to be left at its zero value, so
			// every credential this server loaded claimed BE=0 -- and any synced
			// passkey, which asserts BE=1, was refused at login with "Backup
			// Eligible flag inconsistency". Registration worked, because
			// registration has nothing to compare against; the credential simply
			// could never be used again.
			//
			// UserPresent and UserVerified stay hardcoded, and that is sound
			// rather than lazy: BeginRegistration requires user verification, so
			// no credential reaches storage without both, and the library
			// re-checks the ASSERTED flags on every login regardless of what is
			// claimed here.
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}
	return out
}

// BeginRegistration starts adding an authenticator.
//
// Two options that are policy rather than protocol:
//
//   - RESIDENT KEYS ARE REQUIRED. A non-discoverable credential cannot satisfy
//     conditional UI, which means the user must type an identifier before the
//     browser will offer their passkey -- and that removes most of the reason to
//     have passkeys at all.
//   - USER VERIFICATION IS REQUIRED. Without it a passkey proves possession of a
//     device and nothing else, so it is one factor, not two, and cannot honestly
//     back an acr of 2.
//
// conveyance is the attestation preference, empty for the browser default.
//
// A parameter rather than configuration on the Relying party, because it is a
// per-ORGANISATION decision and one process serves many. Asking every browser
// for attestation because one tenant needs it would collect device identifiers
// from everybody else's users.
func (r *Relying) BeginRegistration(u *User, conveyance string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		// Excluding what the user already has stops a second registration of the
		// same authenticator, which would otherwise look like two credentials and
		// silently satisfy the two-credential rule with one device.
		webauthn.WithExclusions(descriptors(u.Creds)),
	}
	// Only raised when an organisation asked. `none` is the WebAuthn default and
	// the privacy-preserving one: attestation identifies the device model, and
	// some browsers show the user an extra prompt for it.
	if conveyance != "" && conveyance != "none" {
		opts = append(opts, webauthn.WithConveyancePreference(
			protocol.ConveyancePreference(conveyance)))
	}
	return r.w.BeginRegistration(u, opts...)
}

// BeginLogin starts an assertion for a known user.
func (r *Relying) BeginLogin(u *User) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return r.w.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
}

// BeginDiscoverableLogin starts an assertion with no identifier at all.
//
// This is the flow passkeys exist for: the user clicks "sign in", the browser
// offers the credential it holds, and nobody types a username. It only works
// with resident keys, which is why registration requires them.
func (r *Relying) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return r.w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
}

func descriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Descriptor())
	}
	return out
}

// FinishRegistration verifies the authenticator's attestation response.
//
// Delegated straight to the library: this is the part where the cryptography and
// the many structural checks of the WebAuthn spec live, and second-guessing it
// is how implementations introduce the bugs the library exists to avoid.
func (r *Relying) FinishRegistration(u *User, sd webauthn.SessionData, req *http.Request) (*webauthn.Credential, error) {
	return r.w.FinishRegistration(u, sd, req)
}

// FinishLogin verifies an assertion for a known user.
func (r *Relying) FinishLogin(u *User, sd webauthn.SessionData, req *http.Request) (*webauthn.Credential, error) {
	return r.w.FinishLogin(u, sd, req)
}

// FinishDiscoverableLogin verifies an assertion where the user was not known in
// advance; the handler resolves the user from the handle the authenticator
// returned.
func (r *Relying) FinishDiscoverableLogin(h webauthn.DiscoverableUserHandler, sd webauthn.SessionData, req *http.Request) (*webauthn.Credential, error) {
	return r.w.FinishDiscoverableLogin(h, sd, req)
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
