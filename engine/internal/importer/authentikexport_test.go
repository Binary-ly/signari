package importer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// An authentik dump imports as each part can (6.20): groups with their
// members, through usergroup records and through the older ak_groups list,
// and the members of a nested group made members of the groups above it; a
// TOTP device; a passkey under the handle authentik registered it with; a
// link to a source registered here; OAuth2 providers as clients with the
// grants and strict redirect URIs this server implements; a SAML provider with
// its persistent NameIDs. The people keep their UUIDs as the subject. Every
// other thing is named, authentik's own apart, and a second run duplicates
// and resets nothing.
func TestAnAuthentikDumpImportsWhatItCanAndNamesTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'GitHub', 'github', 'c')`, org, fmt.Sprintf("gh-%d", n)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeclareAttribute(ctx, tx, org, store.Attribute{Name: "department", ValueType: "string"}); err != nil {
		t.Fatal(err)
	}
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
	seed := []byte("12345678901234567890")
	credID := []byte(fmt.Sprintf("ak-cred-%d", n))
	adaUUID, bobUUID, ssoUUID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	pw := djangoPBKDF2("pw", "saltsaltsalt", 100)
	install := uuid.NewString()

	dump := fmt.Sprintf(`[
	 {"model":"authentik_core.group","pk":"g-eng","fields":{"name":"Engineering","is_superuser":false,"attributes":{}}},
	 {"model":"authentik_core.group","pk":"g-be","fields":{"name":"Backend","is_superuser":false,"attributes":{"cost":7}}},
	 {"model":"authentik_core.group","pk":"g-da","fields":{"name":"Domain Admins","is_superuser":true}},
	 {"model":"authentik_core.group","pk":"g-old","fields":{"name":"Ops","parent":"g-eng"}},
	 {"model":"authentik_core.groupparentagenode","pk":"x1","fields":{"child":"g-be","parent":"g-eng"}},
	 {"model":"authentik_core.usergroup","pk":1,"fields":{"user":1,"group":"g-be"}},
	 {"model":"authentik_core.source","pk":"s-gh","fields":{"name":"GitHub","slug":"gh-%[1]d"}},
	 {"model":"authentik_core.source","pk":"s-okta","fields":{"name":"Okta","slug":"okta"}},
	 {"model":"authentik_core.usersourceconnection","pk":1,"fields":{"user":1,"source":"s-gh","identifier":"1234"}},
	 {"model":"authentik_core.usersourceconnection","pk":2,"fields":{"user":3,"source":"s-gh","identifier":"5678"}},
	 {"model":"authentik_core.usersourceconnection","pk":3,"fields":{"user":4,"source":"s-okta","identifier":"9"}},
	 {"model":"authentik_sources_oauth.useroauthsourceconnection","pk":1,"fields":{"access_token":null}},
	 {"model":"authentik_core.user","pk":1,"fields":{"username":"ada","name":"Ada L","email":"ada-%[1]d@ak.test",
	  "password":%[2]q,"is_active":true,"uuid":%[3]q,"type":"internal","attributes":{"department":"eng","shoe":42}}},
	 {"model":"authentik_core.user","pk":2,"fields":{"username":"bob","email":"bob-%[1]d@ak.test","password":%[2]q,
	  "is_active":true,"uuid":%[4]q,"ak_groups":["g-da","g-old"]}},
	 {"model":"authentik_core.user","pk":3,"fields":{"username":"sso","email":"sso-%[1]d@ak.test","password":"!",
	  "is_active":true,"uuid":%[5]q,"type":"external"}},
	 {"model":"authentik_core.user","pk":4,"fields":{"username":"stranded","email":"stranded-%[1]d@ak.test",
	  "password":"!","is_active":true,"uuid":%[6]q}},
	 {"model":"authentik_core.user","pk":5,"fields":{"username":"ak-outpost-x","password":"!","is_active":true,
	  "uuid":%[7]q,"type":"internal_service_account"}},
	 {"model":"authentik_core.user","pk":6,"fields":{"username":"svc","password":"!","is_active":true,
	  "uuid":%[8]q,"type":"service_account"}},
	 {"model":"authentik_core.user","pk":7,"fields":{"username":"gone","email":"gone-%[1]d@ak.test","password":%[2]q,
	  "is_active":false,"uuid":%[9]q}},
	 {"model":"authentik_stages_authenticator_totp.totpdevice","pk":1,"fields":{"user":1,"name":"phone",
	  "confirmed":true,"key":%[10]q,"step":30,"t0":0,"digits":6,"drift":0,"last_t":58000000}},
	 {"model":"authentik_stages_authenticator_totp.totpdevice","pk":2,"fields":{"user":2,"name":"half",
	  "confirmed":false,"key":%[10]q,"step":30,"t0":0,"digits":6,"last_t":-1}},
	 {"model":"authentik_stages_authenticator_webauthn.webauthndevice","pk":1,"fields":{"user":1,"name":"YubiKey",
	  "credential_id":%[11]q,"public_key":%[12]q,"sign_count":3,"rp_id":"ak.example.test",
	  "aaguid":"00000000-0000-0000-0000-000000000000"}},
	 {"model":"authentik_core.provider","pk":10,"fields":{"name":"Portal","property_mappings":[1,2]}},
	 {"model":"authentik_core.application","pk":"a1","fields":{"name":"Portal App","slug":"portal","provider":10}},
	 {"model":"authentik_providers_oauth2.oauth2provider","pk":10,"fields":{"client_type":"confidential",
	  "client_id":"portal-%[1]d","client_secret":"s3cret-%[1]d","sub_mode":"hashed_user_id","signing_key":null,
	  "grant_types":["authorization_code","refresh_token","implicit","password"],
	  "logout_uri":"https://portal.ak.test/bc","logout_method":"backchannel",
	  "_redirect_uris":[{"matching_mode":"strict","url":"https://portal.ak.test/cb","redirect_uri_type":"authorization"},
	   {"matching_mode":"regex","url":"https://.*\\.ak\\.test/cb","redirect_uri_type":"authorization"},
	   {"matching_mode":"strict","url":"https://portal.ak.test/bye","redirect_uri_type":"logout"}]}},
	 {"model":"authentik_core.provider","pk":11,"fields":{"name":"Old"}},
	 {"model":"authentik_providers_oauth2.oauth2provider","pk":11,"fields":{"client_type":"public",
	  "client_id":"old-%[1]d","client_secret":"","sub_mode":"user_uuid","signing_key":5,
	  "redirect_uris":"https://old.ak.test/cb\n*"}},
	 {"model":"authentik_core.provider","pk":12,"fields":{"name":"CRM"}},
	 {"model":"authentik_providers_saml.samlprovider","pk":12,"fields":{"acs_url":"https://crm.ak.test/acs",
	  "audience":"urn:crm-%[1]d","name_id_mapping":null,
	  "default_name_id_policy":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}},
	 {"model":"authentik_core.provider","pk":13,"fields":{"name":"Nameless"}},
	 {"model":"authentik_providers_saml.samlprovider","pk":13,"fields":{"acs_url":"https://x.ak.test/acs","audience":""}},
	 {"model":"authentik_core.provider","pk":14,"fields":{"name":"Mapped"}},
	 {"model":"authentik_providers_saml.samlprovider","pk":14,"fields":{"acs_url":"https://m.ak.test/acs",
	  "audience":"urn:mapped-%[1]d","name_id_mapping":"m1"}},
	 {"model":"authentik_core.provider","pk":15,"fields":{"name":"Proxy"}},
	 {"model":"authentik_core.token","pk":9,"fields":{"identifier":"unrelated"}}
	]`, n, pw, adaUUID, bobUUID, ssoUUID, uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(),
		hex.EncodeToString(seed), base64.RawURLEncoding.EncodeToString(credID), base64.RawURLEncoding.EncodeToString(cose))
	exp, err := ParseAuthentik(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportAuthentik(ctx, tx, org, exp, Options{Root: root, InstallID: install})
	if err != nil {
		t.Fatal(err)
	}
	report := strings.Join(slices.Concat(res.Dropped, res.Renamed, res.BuiltIns, res.UsersSkipped,
		res.ClientsSkipped), "\n")

	if res.UsersCreated != 3 || res.SubjectsKept != 3 {
		t.Errorf("%d people created, %d subjects kept; want ada, bob and sso, each keeping theirs:\n%s",
			res.UsersCreated, res.SubjectsKept, report)
	}
	in := func(id string) string {
		t.Helper()
		var names []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(g.name ORDER BY g.name), '{}') FROM core.group_members m
			JOIN core.groups g ON g.id = m.group_id WHERE m.user_id = $1::uuid`, id).Scan(&names); err != nil {
			t.Fatal(err)
		}
		return strings.Join(names, ",")
	}
	if got := in(adaUUID); got != "Backend,Engineering" {
		t.Errorf("ada, in Backend, is in %q; Backend is under Engineering", got)
	}
	if got := in(bobUUID); got != "Domain-Admins,Engineering,Ops" {
		t.Errorf("bob, listed in Domain Admins and Ops, is in %q; Ops's parent is Engineering", got)
	}

	cred, err := store.LoadTOTP(ctx, tx, adaUUID, root)
	if err != nil || !bytes.Equal(cred.Secret, seed) || cred.Algorithm != "SHA1" || cred.Kind != "totp" {
		t.Errorf("ada's TOTP is %+v (%v)", cred, err)
	}
	var last int64
	if err := tx.QueryRow(ctx, `SELECT last_used_counter FROM core.totp_credentials WHERE user_id = $1::uuid`,
		adaUUID).Scan(&last); err != nil || last != 58000000 {
		t.Errorf("ada's last step used is %d (%v), want authentik's last_t", last, err)
	}
	// authentik's own sha256(f"{self.id}-{get_unique_identifier()}"),
	// computed here rather than by the function under test.
	sum := sha256.Sum256([]byte("1-" + install))
	uid := hex.EncodeToString(sum[:])
	var handle []byte
	var rpID string
	if err := tx.QueryRow(ctx, `SELECT u.user_handle, c.rp_id FROM core.webauthn_credentials c
		JOIN core.users u ON u.id = c.user_id WHERE c.credential_id = $1`, credID).Scan(&handle, &rpID); err != nil ||
		string(handle) != uid || rpID != "ak.example.test" {
		t.Errorf("ada's passkey is at %q under handle %q, want %q (%v)", rpID, handle, uid, err)
	}
	var state string
	var links int
	if err := tx.QueryRow(ctx, `SELECT u.migration_state, (SELECT count(*) FROM core.federated_identities f
		WHERE f.user_id = u.id) FROM core.users u WHERE u.id = $1::uuid`, ssoUUID).Scan(&state, &links); err != nil ||
		state != "none" || links != 1 {
		t.Errorf("the person who signs in through GitHub is %s with %d link(s) (%v)", state, links, err)
	}

	clientOf := func(id string) (kind string, grants, redirects, logouts []string) {
		t.Helper()
		if err := tx.QueryRow(ctx, `SELECT c.client_type, c.grant_types,
			COALESCE((SELECT array_agg(redirect_uri ORDER BY redirect_uri) FROM core.client_redirect_uris r
			  WHERE r.client_id = c.client_id), '{}'),
			COALESCE((SELECT array_agg(redirect_uri ORDER BY redirect_uri) FROM core.client_post_logout_redirect_uris l
			  WHERE l.client_id = c.client_id), '{}')
			FROM core.clients c WHERE c.client_id = $1`, id).Scan(&kind, &grants, &redirects, &logouts); err != nil {
			t.Fatalf("client %s: %v", id, err)
		}
		return
	}
	kind, grants, redirects, logouts := clientOf(fmt.Sprintf("portal-%d", n))
	if kind != "confidential" || strings.Join(grants, ",") != "authorization_code,refresh_token" ||
		strings.Join(redirects, ",") != "https://portal.ak.test/cb" || strings.Join(logouts, ",") != "https://portal.ak.test/bye" {
		t.Errorf("portal is %s with %v, redirects %v, logouts %v", kind, grants, redirects, logouts)
	}
	kind, grants, redirects, _ = clientOf(fmt.Sprintf("old-%d", n))
	if kind != "public" || slices.Contains(grants, "client_credentials") ||
		!slices.Contains(grants, "urn:ietf:params:oauth:grant-type:device_code") ||
		strings.Join(redirects, ",") != "https://old.ak.test/cb" {
		t.Errorf("the provider from before grant lists is %s with %v and %v", kind, grants, redirects)
	}

	var format, nameID string
	if err := tx.QueryRow(ctx, `SELECT p.name_id_format, n.name_id FROM core.saml_providers p
		JOIN core.saml_name_ids n ON n.provider_id = p.id WHERE p.entity_id = $1 AND n.user_id = $2::uuid`,
		fmt.Sprintf("urn:crm-%d", n), adaUUID).Scan(&format, &nameID); err != nil || format != "persistent" || nameID != uid {
		t.Errorf("the CRM knows ada as %q (%s), want %q (%v)", nameID, format, uid, err)
	}

	for _, want := range []string{
		"group Domain Admins is Domain-Admins", "group Domain Admins's superuser flag",
		"the nesting of group Backend under Engineering", "group Backend's attributes cost",
		"1 link(s) to source okta", "attribute shoe on 1", "user ak-outpost-x", "svc (a service account",
		"gone-", "inactive in authentik", "stranded-",
		fmt.Sprintf("client portal-%d's subjects (it was sent hashed_user_id", n),
		fmt.Sprintf("client portal-%d's HS256 ID tokens", n), "backchannel logout URI https://portal.ak.test/bc",
		"provider Portal's 2 property mapping(s)", "implicit flow", "password grant",
		fmt.Sprintf("old-%d's hybrid flow", n), "a regular expression", "redirect * (a regular expression",
		"SAML provider Nameless (it states no audience", "a property mapping makes its NameID",
		"provider Proxy (of a kind not carried", "1 authentik_core.token record(s)",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not say %q:\n%s", want, report)
		}
	}
	for _, not := range []string{"useroauthsourceconnection", fmt.Sprintf("client old-%d's subjects", n),
		fmt.Sprintf("client old-%d's HS256", n)} {
		if strings.Contains(report, not) {
			t.Errorf("the report names %q, which came across:\n%s", not, report)
		}
	}

	// Run again: nothing is duplicated, and the step used since stays.
	if _, err := tx.Exec(ctx, `UPDATE core.totp_credentials SET last_used_counter = 58000009 WHERE user_id = $1::uuid`,
		adaUUID); err != nil {
		t.Fatal(err)
	}
	again, err := ImportAuthentik(ctx, tx, org, exp, Options{Root: root, InstallID: install})
	if err != nil {
		t.Fatal(err)
	}
	if again.UsersCreated != 0 || again.GroupsCreated != 0 || again.Memberships != 0 || again.OTPImported != 0 ||
		again.PasskeysImported != 0 || again.ClientsCreated != 0 || again.SAMLProvidersCreated != 0 ||
		again.NameIDsKept != 0 || again.LinksImported != 0 {
		t.Errorf("a second run did %+v", again.Result)
	}
	if err := tx.QueryRow(ctx, `SELECT last_used_counter FROM core.totp_credentials WHERE user_id = $1::uuid`,
		adaUUID).Scan(&last); err != nil || last != 58000009 {
		t.Errorf("a second run moved the step to %d (%v)", last, err)
	}

	// Without the installation ID, the passkeys and NameIDs it made are left
	// behind and said so, in an organisation of its own.
	ctx2, tx2, org2 := importFixture(t)
	fresh := strings.NewReplacer(adaUUID, uuid.NewString(), bobUUID, uuid.NewString(), ssoUUID, uuid.NewString(),
		fmt.Sprint(n), fmt.Sprint(n+1), string(base64.RawURLEncoding.EncodeToString(credID)),
		base64.RawURLEncoding.EncodeToString([]byte("other"))).Replace(dump)
	exp2, err := ParseAuthentik(strings.NewReader(fresh))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ImportAuthentik(ctx2, tx2, org2, exp2, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	r2 := strings.Join(res2.Dropped, "\n")
	if res2.PasskeysImported != 0 || res2.NameIDsKept != 0 || !strings.Contains(r2, "1 passkey(s) (registered under") ||
		!strings.Contains(r2, "the NameIDs SAML provider urn:crm-") {
		t.Errorf("without the installation ID: %d passkeys, %d NameIDs:\n%s", res2.PasskeysImported,
			res2.NameIDsKept, r2)
	}
}
