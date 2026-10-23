package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"

	"signari.dev/engine/internal/importer"
)

// A passkey imported from a realm signs in with no username, through the
// routes a browser calls (0.44). The authenticator answers with the handle the
// passkey was registered under, the realm user's id, and the library refuses
// an assertion whose handle is not the account's; the import once gave every
// account a handle of its own, so each imported passkey was saved and then
// refused at every sign-in.
func TestAPasskeyImportedFromARealmSignsInWithNoUsername(t *testing.T) {
	j := newPasskeyJourney(t)
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256)},
		Curve: 1, XCoord: key.PublicKey.X.FillBytes(make([]byte, 32)), YCoord: key.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	realmID := uuid.NewString()
	cred := &virtualCredential{id: []byte("imported-" + realmID), key: key, rpID: j.rpID, handle: []byte(realmID)}
	q := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
	raw := fmt.Sprintf(`{"realm":"acme","webAuthnPolicyPasswordlessRpId":%q,"users":[{"id":%q,"username":"pk-%s",
	 "email":%q,"enabled":true,"credentials":[
	  {"type":"password","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",
	   "credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":27500}"},
	  {"type":"webauthn-passwordless","credentialData":"%s"}]}]}`, j.rpID, realmID, realmID, j.email,
		q(fmt.Sprintf(`{"credentialId":%q,"counter":0,"credentialPublicKey":%q}`,
			base64.StdEncoding.EncodeToString(cred.id), base64.RawURLEncoding.EncodeToString(cose))))
	realm, err := importer.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := j.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := importer.ImportWith(ctx, tx, j.orgID, realm, importer.Options{})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if res.PasskeysImported != 1 {
		t.Fatalf("%d passkeys imported, not carried: %v", res.PasskeysImported, res.Dropped)
	}

	rec := j.signIn(t, cred)
	if _, _, ok := j.sessionFor(t, rec); !ok {
		t.Fatalf("the imported passkey did not sign in: %d %s", rec.Code, rec.Body)
	}

	// The account holding a handle of its own, as the import once left it:
	// the same passkey is refused.
	if _, err := j.pool.Exec(ctx, `UPDATE core.users SET user_handle = decode(md5(gen_random_uuid()::text)||
		md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')
		WHERE id = $1::uuid`, j.userID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := j.sessionFor(t, j.signIn(t, cred)); ok {
		t.Error("a passkey answering with a handle the account does not hold signed in")
	}
}
