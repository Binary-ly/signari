package passkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"signari.dev/engine/internal/store"
)

// A synced passkey must be able to sign in.
//
// WebAuthn Level 3 (W3C CR Snapshot, 26 May 2026) §6.1.3:
//
//	"The value of the BE flag is set during authenticatorMakeCredential
//	operation and MUST NOT change."
//
// go-webauthn enforces that in validateLogin:
//
//	if credential.Flags.BackupEligible != parsedResponse.Response.AuthenticatorData.Flags.HasBackupEligible() {
//	    return nil, protocol.ErrBadRequest.WithDetails("Backup Eligible flag inconsistency detected during login validation")
//	}
//
// The comparison is against the flags on the credential WE hand it. Those come
// from ToLibrary, which sets UserPresent and UserVerified and nothing else — so
// BackupEligible is false for every credential this server loads.
//
// A backup-eligible authenticator asserts BE=1. false != true, and the login is
// refused. That is every iCloud Keychain, Google Password Manager, Windows Hello
// with sync and 1Password passkey — the overwhelming majority of the ones real
// users have.
//
// The registration ceremony does not compare against anything, so it succeeds.
// The credential is created, stored, shown in the account page, and then cannot
// be used to sign in.
func TestASyncedPasskeyCanSignIn(t *testing.T) {
	for _, tc := range []struct {
		name           string
		backupEligible bool
		backupState    bool
	}{
		{"device-bound (BE=0)", false, false},
		{"synced, not currently backed up (BE=1, BS=0)", true, false},
		{"synced and backed up (BE=1, BS=1)", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertLoginWorks(t, tc.backupEligible, tc.backupState)
		})
	}
}

const testRPID = "example.com"
const testOrigin = "https://example.com"

func assertLoginWorks(t *testing.T, be, bs bool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := randomBytes(t, 32)
	userHandle := randomBytes(t, 64)

	rp, err := New(testRPID, "Test", testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	// The stored credential, exactly as this server would load it.
	stored := []store.WebAuthnCredential{{
		CredentialID: credID,
		PublicKey:    coseES256(key),
		SignCount:    0,
		RPID:         testRPID,
		// Whatever the registration recorded about backup eligibility has to
		// survive to here, or the comparison below cannot be right.
		BackupEligible: be,
	}}
	user := &User{
		ID: userHandle, Name: "u@example.com", DisplayName: "U",
		Creds: ToLibrary(stored),
	}

	challenge := randomBytes(t, 32)
	sd := webauthn.SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(challenge),
		UserID:               userHandle,
		AllowedCredentialIDs: [][]byte{credID},
		UserVerification:     "required",
	}

	// clientDataJSON for an assertion.
	clientData := fmt.Sprintf(
		`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge), testOrigin)

	// authenticatorData: rpIdHash(32) || flags(1) || signCount(4).
	rpHash := sha256.Sum256([]byte(testRPID))
	var flags byte = 0x01 | 0x04 // UP | UV
	if be {
		flags |= 0x08 // BE
	}
	if bs {
		flags |= 0x10 // BS
	}
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, 1)

	// The signature is over authenticatorData || SHA-256(clientDataJSON).
	cdHash := sha256.Sum256([]byte(clientData))
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64([]byte(clientData)),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, "/passkey/login", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	cred, err := rp.FinishLogin(user, sd, req)
	if err != nil {
		t.Fatalf("a credential with BE=%v BS=%v could not sign in: %v\n\n"+
			"WebAuthn L3 §6.1.3 makes BE immutable after registration, and the "+
			"library compares the asserted flag against the one on the credential "+
			"we supply. If this server does not carry backup eligibility from "+
			"registration through to login, every synced passkey registers "+
			"successfully and can never be used again.", be, bs, err)
	}
	if cred.Flags.BackupEligible != be {
		t.Errorf("the verified credential reports BackupEligible=%v, want %v",
			cred.Flags.BackupEligible, be)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// coseES256 encodes a P-256 public key as a COSE_Key, the form an authenticator
// returns and the form we store.
//
//	{1: 2 (kty EC2), 3: -7 (alg ES256), -1: 1 (crv P-256), -2: x, -3: y}
func coseES256(k *ecdsa.PrivateKey) []byte {
	x := k.PublicKey.X.FillBytes(make([]byte, 32))
	y := k.PublicKey.Y.FillBytes(make([]byte, 32))
	out := []byte{
		0xa5,       // map(5)
		0x01, 0x02, // 1: 2
		0x03, 0x26, // 3: -7
		0x20, 0x01, // -1: 1
		0x21, 0x58, 0x20, // -2: bytes(32)
	}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20) // -3: bytes(32)
	out = append(out, y...)
	return out
}
