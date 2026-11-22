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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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
//
// mds, when not nil, is the FIDO metadata catalogue: a certificate-chain
// attestation for a model it lists is checked against that model's roots, and
// a model marked revoked or compromised is refused. Nil means no catalogue,
// and then no attestation can vouch for an AAGUID.
//
// related are further origins a credential under rpID may be used from
// (WebAuthn §5.11, related origin requests), each checked by
// CheckRelatedOrigin; the browser allows them only when the RP ID's
// /.well-known/webauthn lists them too.
func New(rpID, displayName string, issuer string, mds metadata.Provider, related ...string) (*Relying, error) {
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
	for _, o := range related {
		if err := CheckRelatedOrigin(o); err != nil {
			return nil, err
		}
		if !contains(origins, o) {
			origins = append(origins, o)
		}
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
		MDS:           mds,
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

// CheckRelatedOrigin refuses what cannot be a related origin: it is a web
// origin, so a scheme, a host and an optional port, and nothing else; and it is
// https, since a ceremony over an interceptable connection is what an origin
// list exists to rule out. http is allowed for localhost alone, as browsers
// treat it as a secure context.
func CheckRelatedOrigin(o string) error {
	u, err := url.Parse(o)
	switch {
	case err != nil || u.Host == "":
		return fmt.Errorf("passkeys: related origin %q is not an origin such as https://example.co.uk", o)
	case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("passkeys: related origin %q has a path, query or credentials; "+
			"an origin is a scheme, a host and a port", o)
	case u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost"):
		return fmt.Errorf("passkeys: related origin %q is not https", o)
	case o != u.Scheme+"://"+strings.ToLower(u.Host):
		// Lower case, as a browser serialises the origin it compares: one
		// listed in capitals would never match.
		return fmt.Errorf("passkeys: related origin %q is not written as one: use %s",
			o, u.Scheme+"://"+strings.ToLower(u.Host))
	}
	return nil
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
			// UserPresent and UserVerified stay hardcoded. The library re-checks
			// the ASSERTED flags on every login whatever is claimed here, refusing
			// an assertion without verification when the ceremony required it,
			// and the credential it returns carries this UserVerified forward
			// unchanged -- which is why a sign-in reads the assertion's own flag
			// (FinishDiscoverableLogin) and never this one.
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

// Ceremony is what an organisation asks of an authenticator (migration 0170):
// a per-ORGANISATION decision, so a parameter rather than configuration on
// the Relying party -- one process serves many.
type Ceremony struct {
	// Conveyance is the attestation preference, empty or none for the browser
	// default. Raised only when an organisation asked: attestation identifies
	// the device model, and some browsers show an extra prompt for it.
	Conveyance string
	// UserVerification is required or preferred. Required by default: without
	// it a passkey proves possession of a device and nothing else, one factor,
	// and its sign-in is single-factor.
	UserVerification string
	// ResidentKey is required, preferred or discouraged. Required by default:
	// a non-discoverable credential cannot sign in without a username first.
	// It still serves as a second factor, where the account is known.
	ResidentKey string
	// Attachment is empty for any, platform or cross-platform.
	Attachment string
	// Algorithms are COSE identifiers in preference order; empty is the
	// library's own list.
	Algorithms []int
	// Timeout is how long the browser waits, and the server holds the
	// challenge.
	Timeout time.Duration
	// Hints are WebAuthn's security-key, client-device and hybrid.
	Hints []string
}

// DefaultCeremony is what the code asked before an organisation could choose.
var DefaultCeremony = Ceremony{UserVerification: "required", ResidentKey: "required",
	Timeout: 5 * time.Minute}

func (c Ceremony) uv() protocol.UserVerificationRequirement {
	if c.UserVerification == "preferred" {
		return protocol.VerificationPreferred
	}
	return protocol.VerificationRequired
}

func (c Ceremony) hints() []protocol.PublicKeyCredentialHints {
	out := make([]protocol.PublicKeyCredentialHints, 0, len(c.Hints))
	for _, h := range c.Hints {
		out = append(out, protocol.PublicKeyCredentialHints(h))
	}
	return out
}

// expire holds the server to the ceremony's own timeout, which the library
// enforces on the session it finishes against.
func (c Ceremony) expire(sd *webauthn.SessionData) {
	if c.Timeout > 0 && sd != nil {
		sd.Expires = time.Now().Add(c.Timeout)
	}
}

// BeginRegistration starts adding an authenticator under c.
func (r *Relying) BeginRegistration(u *User, c Ceremony) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	sel := protocol.AuthenticatorSelection{UserVerification: c.uv()}
	switch c.ResidentKey {
	case "preferred":
		sel.ResidentKey = protocol.ResidentKeyRequirementPreferred
	case "discouraged":
		sel.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
	default:
		sel.ResidentKey = protocol.ResidentKeyRequirementRequired
		sel.RequireResidentKey = protocol.ResidentKeyRequired()
	}
	switch c.Attachment {
	case "platform":
		sel.AuthenticatorAttachment = protocol.Platform
	case "cross-platform":
		sel.AuthenticatorAttachment = protocol.CrossPlatform
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(sel),
		// Excluding what the user already has stops a second registration of the
		// same authenticator, which would otherwise look like two credentials and
		// silently satisfy the two-credential rule with one device.
		webauthn.WithExclusions(descriptors(u.Creds)),
		// So a credential that may or may not be discoverable says which it is.
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	}
	if len(c.Algorithms) > 0 {
		params := make([]protocol.CredentialParameter, 0, len(c.Algorithms))
		for _, a := range c.Algorithms {
			params = append(params, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.COSEAlgorithmIdentifier(a)})
		}
		opts = append(opts, webauthn.WithCredentialParameters(params))
	}
	if len(c.Hints) > 0 {
		opts = append(opts, webauthn.WithPublicKeyCredentialHints(c.hints()))
	}
	if c.Conveyance != "" && c.Conveyance != "none" {
		opts = append(opts, webauthn.WithConveyancePreference(
			protocol.ConveyancePreference(c.Conveyance)))
	}
	creation, sd, err := r.w.BeginRegistration(u, opts...)
	if err == nil && c.Timeout > 0 {
		creation.Response.Timeout = int(c.Timeout.Milliseconds())
		c.expire(sd)
	}
	return creation, sd, err
}

// BeginSecondFactor starts an assertion for a known user, asked for after a
// password.
//
// User verification is preferred, not required. The password is the knowledge
// factor and the key is asked to prove possession; requiring a PIN or a
// fingerprint as well would refuse a security key that has no PIN set. A key
// that does not verify the user is a single-factor cryptographic authenticator
// under SP 800-63B's syncable-authenticator appendix, which with the password
// is still two factors. "Preferred" is what that appendix says a verifier SHALL
// indicate (docs/security-review-nist-800-63b.md, the UV row).
//
// verify asks for verification instead, for a sign-in whose first factor was
// already a key: another touch of a key proves possession a second time, not
// a second factor.
func (r *Relying) BeginSecondFactor(u *User, c Ceremony, verify bool) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	uv := protocol.VerificationPreferred
	if verify {
		uv = protocol.VerificationRequired
	}
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(uv)}
	if len(c.Hints) > 0 {
		opts = append(opts, webauthn.WithAssertionPublicKeyCredentialHints(c.hints()))
	}
	assertion, sd, err := r.w.BeginLogin(u, opts...)
	if err == nil && c.Timeout > 0 {
		assertion.Response.Timeout = int(c.Timeout.Milliseconds())
		c.expire(sd)
	}
	return assertion, sd, err
}

// FinishSecondFactor verifies a second-factor assertion. It takes the
// assertion's JSON rather than a request, because the page posts it as one
// field of a form: completing a sign-in may redirect to the application or show
// a prompt, and only a form submission can follow either. verified is this
// assertion's own flag, as at FinishDiscoverableLogin.
func (r *Relying) FinishSecondFactor(u *User, sd webauthn.SessionData, assertion []byte) (cred *webauthn.Credential, verified bool, err error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return nil, false, err
	}
	if cred, err = r.w.ValidateLogin(u, sd, parsed); err != nil {
		return nil, false, err
	}
	return cred, parsed.Response.AuthenticatorData.Flags.UserVerified(), nil
}

// BeginDiscoverableLogin starts an assertion with no identifier at all, under
// c's user verification, hints and timeout.
//
// This is the flow passkeys exist for: the user clicks "sign in", the browser
// offers the credential it holds, and nobody types a username. It only works
// with resident keys, which is why registration requires them by default.
func (r *Relying) BeginDiscoverableLogin(c Ceremony) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	opts := []webauthn.LoginOption{webauthn.WithUserVerification(c.uv())}
	if len(c.Hints) > 0 {
		opts = append(opts, webauthn.WithAssertionPublicKeyCredentialHints(c.hints()))
	}
	assertion, sd, err := r.w.BeginDiscoverableLogin(opts...)
	if err == nil && c.Timeout > 0 {
		assertion.Response.Timeout = int(c.Timeout.Milliseconds())
		c.expire(sd)
	}
	return assertion, sd, err
}

func descriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Descriptor())
	}
	return out
}

// FinishRegistration verifies the authenticator's attestation response, and
// says whether the credential is discoverable: certainly when c required a
// resident key, otherwise as the client reported it through credProps, and not
// when it reported nothing.
//
// The verification is delegated straight to the library: this is the part
// where the cryptography and the many structural checks of the WebAuthn spec
// live, and second-guessing it is how implementations introduce the bugs the
// library exists to avoid.
func (r *Relying) FinishRegistration(u *User, sd webauthn.SessionData, req *http.Request, c Ceremony) (*webauthn.Credential, bool, error) {
	parsed, err := protocol.ParseCredentialCreationResponse(req)
	if err != nil {
		return nil, false, err
	}
	cred, err := r.w.CreateCredential(u, sd, parsed)
	if err != nil {
		return nil, false, err
	}
	discoverable := c.ResidentKey == "" || c.ResidentKey == "required"
	if props := parsed.ClientExtensionResults.CredProps; !discoverable && props != nil && props.RK != nil {
		discoverable = *props.RK
	}
	return cred, discoverable, nil
}

// FinishLogin verifies an assertion for a known user.
func (r *Relying) FinishLogin(u *User, sd webauthn.SessionData, req *http.Request) (*webauthn.Credential, error) {
	return r.w.FinishLogin(u, sd, req)
}

// FinishDiscoverableLogin verifies an assertion where the user was not known in
// advance; the handler resolves the user from the handle the authenticator
// returned. verified is whether THIS assertion verified the user: the
// credential the library returns carries the record's flag, set at
// registration, so under a preferred policy it would say a sign-in with no PIN
// or biometric had one.
func (r *Relying) FinishDiscoverableLogin(h webauthn.DiscoverableUserHandler, sd webauthn.SessionData,
	req *http.Request) (cred *webauthn.Credential, verified bool, err error) {
	parsed, err := protocol.ParseCredentialRequestResponse(req)
	if err != nil {
		return nil, false, err
	}
	cred, err = r.w.ValidateDiscoverableLogin(h, sd, parsed)
	if err != nil {
		return nil, false, err
	}
	return cred, parsed.Response.AuthenticatorData.Flags.UserVerified(), nil
}

// Reason renders a ceremony failure for the operator's log.
//
// go-webauthn's error prints only its Details, and many of its refusals carry
// the explanation in the type and debug fields alone, so a refused
// registration logged as err="" -- nothing to tell a forged attestation from a
// wrong origin. Logged, never returned: the caller tells the browser only that
// the response was rejected.
func Reason(err error) string {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		return fmt.Sprint(err)
	}
	parts := []string{}
	for _, p := range []string{pe.Type, pe.Details, pe.DevInfo} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if pe.Err != nil {
		parts = append(parts, pe.Err.Error())
	}
	return strings.Join(parts, ": ")
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
