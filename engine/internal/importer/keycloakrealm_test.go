package importer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A realm with groups, roles, OTP, passkeys, provider links, attributes and
// SAML and OIDC clients imports as each can (6.20): the groups by path with
// their members, the realm roles as groups, TOTP and HOTP seeds sealed with
// the counter as this server keeps it, the passkey under the realm's relying
// party ID, the links to a provider registered here, a SAML client as a
// service provider. Everything else is named in the report, Keycloak's own
// apart, and a second run duplicates and resets nothing.
//
// What applications know people by comes too (0.44): the user's id is the
// subject every token is sent, the user handle their passkeys answer with,
// and a SAML client's persistent NameID. Where an account here already holds
// one, the report says so.
func TestAKeycloakRealmImportsWhatItCanAndNamesTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{5}, 32))
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

	seed := []byte("12345678901234567890")
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
	credID := []byte(fmt.Sprintf("cred-%d", n))
	adaID, tokenID, preID := uuid.NewString(), uuid.NewString(), uuid.NewString()

	// Someone already here with a passkey of their own, whom the realm also
	// holds, with a passkey under another handle.
	var pre string
	if err := tx.QueryRow(ctx, `INSERT INTO core.users (org_id, email, user_handle)
		VALUES ($1::uuid, $2, decode(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text)||
		        md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'hex')) RETURNING id::text`, org,
		fmt.Sprintf("pre-%d@example.test", n)).Scan(&pre); err != nil {
		t.Fatal(err)
	}
	if _, why, err := importPasskey(ctx, tx, org, pre, passkey{RPID: "example.test",
		ID: []byte(fmt.Sprintf("own-%d", n)), PublicKey: cose}); err != nil || why != "" {
		t.Fatal(why, err)
	}
	q := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
	pw := `{"type":"password","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}",` +
		`"credentialData":"{\"algorithm\":\"pbkdf2-sha256\",\"hashIterations\":27500}"}`
	totp := `{"type":"otp","secretData":"` + q(`{"value":"`+base32.StdEncoding.EncodeToString(seed)+`"}`) +
		`","credentialData":"` + q(`{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA256","secretEncoding":"BASE32"}`) + `"}`
	hotp := `{"type":"otp","secretData":"` + q(`{"value":"`+string(seed)+`"}`) +
		`","credentialData":"` + q(`{"subType":"hotp","digits":6,"counter":5,"algorithm":"HmacSHA1"}`) + `"}`
	webauthn := func(id []byte) string {
		return `{"type":"webauthn-passwordless","userLabel":"Laptop","credentialData":"` +
			q(fmt.Sprintf(`{"aaguid":"ee882879-721c-4913-9775-3dfcce97072a","credentialId":"%s","counter":7,`+
				`"credentialPublicKey":"%s","attestationStatementFormat":"none","transports":["internal"]}`,
				base64.StdEncoding.EncodeToString(id), base64.RawURLEncoding.EncodeToString(cose))) + `"}`
	}
	passwordless := webauthn(credID)
	raw := fmt.Sprintf(`{"realm":"acme","webAuthnPolicyPasswordlessRpId":"example.test",
	 "groups":[{"name":"Engineering Team","path":"/Engineering Team","attributes":{"cost":["7"]},
	   "subGroups":[{"name":"Backend","path":"/Engineering Team/Backend","realmRoles":["deployer"]}]}],
	 "roles":{"realm":[{"name":"offline_access"},{"name":"uma_authorization"},{"name":"default-roles-acme","composite":true},
	   {"name":"deployer"},{"name":"auditor","composite":true}]},
	 "users":[
	  {"id":"%[6]s","username":"ada","email":"ada-%[1]d@example.test","enabled":true,"credentials":[%[2]s,%[3]s,%[4]s],
	   "groups":["/Engineering Team/Backend"],"realmRoles":["deployer","offline_access","default-roles-acme"],
	   "clientRoles":{"billing":["viewer"]},"federatedIdentities":[{"identityProvider":"gh-%[1]d","userId":"1234"}],
	   "attributes":{"department":["eng"],"shoe":["42"],"saml.persistent.name.id.for.urn:crm-%[1]d":["G-ada"]}},
	  {"username":"linked","email":"linked-%[1]d@example.test","enabled":true,
	   "federatedIdentities":[{"identityProvider":"gh-%[1]d","userId":"5678"}]},
	  {"username":"stranded","email":"stranded-%[1]d@example.test","enabled":true,
	   "federatedIdentities":[{"identityProvider":"okta","userId":"9"}]},
	  {"id":"%[7]s","username":"token","email":"token-%[1]d@example.test","enabled":true,"credentials":[%[2]s,%[5]s],
	   "attributes":{"saml.persistent.name.id.for.*":["G-token"]}},
	  {"id":"%[8]s","username":"pre","email":"pre-%[1]d@example.test","enabled":true,"credentials":[%[2]s,%[9]s]}],
	 "clients":[
	  {"clientId":"account","protocol":"openid-connect"},
	  {"clientId":"urn:wiki-%[1]d","name":"Wiki","protocol":"saml","enabled":true,
	   "attributes":{"saml_name_id_format":"email","saml_assertion_consumer_url_post":"https://wiki.example.test/acs"}},
	  {"clientId":"urn:crm-%[1]d","name":"CRM","protocol":"saml","enabled":true,
	   "attributes":{"saml_name_id_format":"persistent","saml_assertion_consumer_url_post":"https://crm.example.test/acs"}},
	  {"clientId":"urn:legacy-%[1]d","protocol":"saml","attributes":{"saml_name_id_format":"username"},
	   "redirectUris":["https://legacy.example.test/acs"]},
	  {"clientId":"urn:bare-%[1]d","protocol":"saml","redirectUris":["https://bare.example.test/acs"]},
	  {"clientId":"portal-%[1]d","name":"Portal","protocol":"openid-connect","enabled":true,"standardFlowEnabled":true,
	   "implicitFlowEnabled":true,"directAccessGrantsEnabled":true,"redirectUris":["https://portal.example.test/cb"],
	   "protocolMappers":[{"name":"dept","protocolMapper":"oidc-usermodel-attribute-mapper"}]}]}`,
		n, pw, totp, passwordless, hotp, adaID, tokenID, preID, webauthn([]byte(fmt.Sprintf("pre-cred-%d", n))))
	realm, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportWith(ctx, tx, org, realm, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	report := strings.Join(append(append(append(res.Dropped, res.Renamed...), res.BuiltIns...),
		append(res.UsersSkipped, res.ClientsSkipped...)...), "\n")

	if res.UsersCreated != 3 || len(res.UsersSkipped) != 1 || !strings.Contains(res.UsersSkipped[0], "stranded") {
		t.Errorf("users: %d created, skipped %v", res.UsersCreated, res.UsersSkipped)
	}
	userID := func(name string) string {
		t.Helper()
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM core.users WHERE org_id = $1::uuid AND username = $2`,
			org, name).Scan(&id); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return id
	}
	var groups []string
	if err := tx.QueryRow(ctx, `SELECT array_agg(g.name ORDER BY g.name) FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id WHERE m.user_id = $1::uuid`, userID("ada")).Scan(&groups); err != nil ||
		strings.Join(groups, ",") != "Engineering-Team.Backend,role.deployer" {
		t.Errorf("ada is in %v (%v)", groups, err)
	}
	cred, err := store.LoadTOTP(ctx, tx, userID("ada"), root)
	if err != nil || !bytes.Equal(cred.Secret, seed) || cred.Algorithm != "SHA256" || cred.Kind != "totp" {
		t.Errorf("ada's OTP is %+v (%v)", cred, err)
	}
	var kind string
	var last int64
	if err := tx.QueryRow(ctx, `SELECT kind, last_used_counter FROM core.totp_credentials WHERE user_id = $1::uuid`,
		userID("token")).Scan(&kind, &last); err != nil || kind != "hotp" || last != 4 {
		t.Errorf("the HOTP token is %s at %d (%v); Keycloak's 5 is the next counter, so 4 was the last used", kind, last, err)
	}
	var rpID string
	var discoverable bool
	if err := tx.QueryRow(ctx, `SELECT rp_id, is_discoverable FROM core.webauthn_credentials WHERE credential_id = $1`,
		credID).Scan(&rpID, &discoverable); err != nil || rpID != "example.test" || !discoverable {
		t.Errorf("the passkey is at %q, discoverable %v (%v)", rpID, discoverable, err)
	}
	var links int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.federated_identities f JOIN core.users u ON u.id = f.user_id
		WHERE u.org_id = $1::uuid`, org).Scan(&links); err != nil || links != 2 {
		t.Errorf("%d provider links (%v)", links, err)
	}
	var state string
	var passwords int
	if err := tx.QueryRow(ctx, `SELECT u.migration_state, (SELECT count(*) FROM core.password_credentials p
		WHERE p.user_id = u.id) FROM core.users u WHERE u.id = $1::uuid`, userID("linked")).Scan(&state, &passwords); err != nil ||
		state != "none" || passwords != 0 {
		t.Errorf("the person who signs in through the provider is %s with %d password(s)", state, passwords)
	}
	var format, acs string
	if err := tx.QueryRow(ctx, `SELECT p.name_id_format, a.url FROM core.saml_providers p
		JOIN core.saml_acs_urls a ON a.provider_id = p.id WHERE p.org_id = $1::uuid AND p.entity_id = $2`, org,
		fmt.Sprintf("urn:wiki-%d", n)).Scan(&format, &acs); err != nil ||
		format != "emailAddress" || acs != "https://wiki.example.test/acs" {
		t.Errorf("the SAML provider is %s at %s (%v)", format, acs, err)
	}
	for _, want := range []string{
		"group /Engineering Team is Engineering-Team", "realm role deployer is group role.deployer",
		"the roles group /Engineering Team/Backend grants", "group /Engineering Team's attributes cost",
		"the roles realm role auditor contains", "1 link(s) to provider okta", "client role billing/viewer, held by 1",
		"attribute shoe on 1", "urn:legacy", "sends the username", "implicit flow", "direct access grants",
		"mapper dept", "client account", "role offline_access", "role default-roles-acme",
		fmt.Sprintf(`SAML client urn:bare-%d (its NameID format "" sends the username`, n),
		"'s subject " + preID + ": applications are sent " + pre + " for them here (an account here already held them",
		"'s passkeys (the account here has passkeys of its own",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not say %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "saml.persistent") {
		t.Errorf("a persistent NameID is reported as an attribute:\n%s", report)
	}

	// Applications meet the same people: the id is the subject, the handle
	// the passkeys', the NameIDs the service provider's.
	if userID("ada") != adaID || userID("token") != tokenID || res.SubjectsKept != 2 {
		t.Errorf("ada is %s, not %s, token %s, not %s; %d subjects kept", userID("ada"), adaID, userID("token"),
			tokenID, res.SubjectsKept)
	}
	var handle []byte
	if err := tx.QueryRow(ctx, `SELECT user_handle FROM core.users WHERE id = $1::uuid`, adaID).Scan(&handle); err != nil ||
		string(handle) != adaID {
		t.Errorf("ada's handle is %q, not her id as Keycloak registered her passkeys (%v)", handle, err)
	}
	nameID := func(user string) string {
		t.Helper()
		var v string
		if err := tx.QueryRow(ctx, `SELECT n.name_id FROM core.saml_name_ids n JOIN core.saml_providers p
			ON p.id = n.provider_id WHERE p.entity_id = $1 AND n.user_id = $2::uuid`, fmt.Sprintf("urn:crm-%d", n),
			user).Scan(&v); err != nil {
			return err.Error()
		}
		return v
	}
	if nameID(adaID) != "G-ada" || nameID(tokenID) != "G-token" || res.NameIDsKept != 2 {
		t.Errorf("the CRM knows ada as %q and token as %q; %d NameIDs kept", nameID(adaID), nameID(tokenID),
			res.NameIDsKept)
	}
	var preKeys int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.webauthn_credentials WHERE user_id = $1::uuid`,
		pre).Scan(&preKeys); err != nil || preKeys != 1 {
		t.Errorf("the person already here holds %d passkeys, want their own one alone (%v)", preKeys, err)
	}

	// Run again, nothing is duplicated or reset: the HOTP counter used since
	// is the token's, not the export's.
	if _, err := tx.Exec(ctx, `UPDATE core.totp_credentials SET last_used_counter = 9 WHERE user_id = $1::uuid`,
		userID("token")); err != nil {
		t.Fatal(err)
	}
	again, err := ImportWith(ctx, tx, org, realm, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if again.UsersCreated != 0 || again.GroupsCreated != 0 || again.Memberships != 0 || again.OTPImported != 0 ||
		again.PasskeysImported != 0 || again.SAMLProvidersCreated != 0 || again.ClientsCreated != 0 ||
		again.NameIDsKept != 0 || again.SubjectsKept != 2 {
		t.Errorf("a second run did %+v", again)
	}
	if r := strings.Join(again.Dropped, "\n"); strings.Contains(r, "ada's") && strings.Contains(r, "subject") {
		t.Errorf("a second run says ada's subject was not kept:\n%s", r)
	}
	if err := tx.QueryRow(ctx, `SELECT last_used_counter FROM core.totp_credentials WHERE user_id = $1::uuid`,
		userID("token")).Scan(&last); err != nil || last != 9 {
		t.Errorf("a second run moved the HOTP counter to %d (%v)", last, err)
	}

	// The same usernames under other addresses are somebody else's here:
	// reported, where they once failed the whole import.
	other := strings.ReplaceAll(raw, fmt.Sprintf("-%d", n), fmt.Sprintf("-%d-b", n))
	realm2, err := Parse(strings.NewReader(other))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ImportWith(ctx, tx, org, realm2, Options{Root: root})
	if err != nil {
		t.Fatalf("an import meeting a username held by another account failed: %v", err)
	}
	if res2.UsersCreated != 0 || !strings.Contains(strings.Join(res2.UsersSkipped, "\n"), "the username ada belongs to another account") {
		t.Errorf("a username held by another account: %d created, skipped %v", res2.UsersCreated, res2.UsersSkipped)
	}

	// Without the root key, the seeds are left behind and said so.
	fresh := strings.ReplaceAll(other, `"username":"`, `"username":"c-`)
	realm3, err := Parse(strings.NewReader(fresh))
	if err != nil {
		t.Fatal(err)
	}
	res3, err := ImportWith(ctx, tx, org, realm3, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res3.OTPImported != 0 || !strings.Contains(strings.Join(res3.Dropped, "\n"), "needs SIGNARI_ROOT_KEY") {
		t.Errorf("without the root key: %d OTP, dropped %v", res3.OTPImported, res3.Dropped)
	}
	var logouts []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(redirect_uri), '{}') FROM core.client_post_logout_redirect_uris
		WHERE client_id = $1`, fmt.Sprintf("portal-%d", n)).Scan(&logouts); err != nil ||
		strings.Join(logouts, ",") != "https://portal.example.test/cb" {
		t.Errorf("portal's logout may return to %v (%v); stating none, Keycloak returns to its redirect URIs", logouts, err)
	}

	// They are new people, holding ids and handles others here hold: made
	// with their own, and said so. The one whose id nobody took (pre's was
	// not, since pre kept the account they had) keeps it, and their passkey.
	r3 := strings.Join(res3.Dropped, "\n")
	if res3.SubjectsKept != 1 || res3.PasskeysImported != 1 ||
		!strings.Contains(r3, "'s subject "+adaID) || !strings.Contains(r3, "another account here holds that id") ||
		!strings.Contains(r3, "'s passkeys (another account here holds their handle") {
		t.Errorf("people whose id and handle are held: %d subjects kept, %d passkeys:\n%s", res3.SubjectsKept,
			res3.PasskeysImported, r3)
	}
}

// Where RP-initiated logout may return a browser, read as Keycloak reads it.
func TestKeycloakPostLogoutRedirectsAreReadAsKeycloakReadsThem(t *testing.T) {
	redirects := []string{"https://a.test/cb"}
	for attr, want := range map[string]string{
		"":                                   "https://a.test/cb",
		"-":                                  "",
		"https://a.test/bye ## +":            "https://a.test/bye,https://a.test/cb",
		"https://a.test/bye##https://b.test": "https://a.test/bye,https://b.test",
	} {
		got := keycloakPostLogout(keycloakClient{RedirectURIs: redirects,
			Attributes: map[string]string{"post.logout.redirect.uris": attr}})
		if strings.Join(got, ",") != want {
			t.Errorf("post.logout.redirect.uris %q reads as %v, want %s", attr, got, want)
		}
	}
}
