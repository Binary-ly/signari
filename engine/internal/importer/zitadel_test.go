package importer

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// A Zitadel export's organisation imports as each part can (6.20): people
// with their bcrypt hash, names and verified address; project roles as
// groups, with the grants of them; the TOTP secret; links to an IdP whose
// name is a provider's slug here; metadata an attribute is declared for.
// What the export holds and this cannot carry is named: the subjects, the
// OIDC applications, whose client IDs the export does not hold, machine users,
// administrative roles, and every other field. Read in either spelling.
func TestAZitadelExportImportsWhatItCanAndNamesTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, 'Corporate', 'oidc', 'c')`, org, fmt.Sprintf("corporate-sso-%d", n)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeclareAttribute(ctx, tx, org, store.Attribute{Name: "costcenter", ValueType: "string"}); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("pw-"+fmt.Sprint(n)), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("12345678901234567890")
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	export := fmt.Sprintf(`{"orgs":[{"orgId":"100","org":{"name":"Acme"},
	 "projects":[{"projectId":"200","project":{"name":"Billing App"}}],
	 "projectRoles":[{"projectId":"200","roleKey":"admin","displayName":"Admin"},{"projectId":"200","roleKey":"viewer"}],
	 "oidcApps":[{"appId":"300","app":{"projectId":"200","name":"web","redirectUris":["https://billing.z.test/cb"],
	   "postLogoutRedirectUris":["https://billing.z.test/bye"]}}],
	 "humanUsers":[
	  {"userId":"401","state":"USER_STATE_ACTIVE","user":{"userName":"ada","profile":{"firstName":"Ada","lastName":"L",
	   "nickName":"al"},"email":{"email":"ada-%[1]d@z.test","isEmailVerified":true},"hashedPassword":{"value":%[2]q},
	   "otpCode":%[3]q}},
	  {"userId":"402","state":"USER_STATE_ACTIVE","user":{"userName":"sso","email":{"email":"sso-%[1]d@z.test"}}},
	  {"userId":"403","state":"USER_STATE_INACTIVE","user":{"userName":"gone","email":{"email":"gone-%[1]d@z.test"},
	   "hashedPassword":{"value":%[2]q}}},
	  {"userId":"404","state":4,"user":{"userName":"locked","hashedPassword":{"value":%[2]q}}}],
	 "machineUsers":[{"userId":"500","user":{"userName":"ci-bot"}}],
	 "userGrants":[{"userId":"401","projectId":"200","roleKeys":["admin","ghost"]}],
	 "orgMembers":[{"userId":"401","roles":["ORG_OWNER"]}],
	 "userMetadata":[{"id":"401","key":"costcenter","value":%[4]q},{"id":"401","key":"badge","value":%[5]q}],
	 "userLinks":[{"userId":"402","idpId":"9","idpName":"Corporate SSO %[1]d","providedUserId":"u-402"},
	  {"userId":"401","idpId":"8","idpName":"Elsewhere","providedUserId":"x"}],
	 "actions":[{"actionId":"1"},{"actionId":"2"}],
	 "loginPolicy":{"allowRegister":true}}]}`,
		n, hash, base32.StdEncoding.EncodeToString(seed), b64("cc-7"), b64("B12"))
	exp, err := ParseZitadel(strings.NewReader(export))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportZitadel(ctx, tx, org, exp, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	report := strings.Join(slices.Concat(res.Dropped, res.Renamed, res.UsersSkipped, res.ClientsSkipped), "\n")

	if res.UsersCreated != 2 {
		t.Errorf("%d people created, want ada and the person who signs in through Corporate SSO:\n%s",
			res.UsersCreated, report)
	}
	var ada, given, display string
	var verified bool
	if err := tx.QueryRow(ctx, `SELECT id::text, given_name, display_name, email_verified_at IS NOT NULL
		FROM core.users WHERE org_id = $1::uuid AND username = 'ada'`, org).Scan(&ada, &given, &display, &verified); err != nil ||
		given != "Ada" || display != "Ada L" || !verified {
		t.Errorf("ada is %q, %q, verified %v (%v)", given, display, verified, err)
	}
	var stored string
	if err := tx.QueryRow(ctx, `SELECT hash FROM core.password_credentials WHERE user_id = $1::uuid`, ada).
		Scan(&stored); err != nil || stored != string(hash) {
		t.Errorf("ada's password hash is %q (%v)", stored, err)
	}
	var groups []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(g.name ORDER BY g.name), '{}') FROM core.group_members m
		JOIN core.groups g ON g.id = m.group_id WHERE m.user_id = $1::uuid`, ada).Scan(&groups); err != nil ||
		strings.Join(groups, ",") != "Billing-App.admin" {
		t.Errorf("ada is in %v (%v)", groups, err)
	}
	cred, err := store.LoadTOTP(ctx, tx, ada, root)
	if err != nil || !bytes.Equal(cred.Secret, seed) || cred.Algorithm != "SHA1" || cred.Digits != 6 ||
		cred.Period != 30*time.Second {
		t.Errorf("ada's TOTP is %+v (%v)", cred, err)
	}
	var links int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.federated_identities f JOIN core.users u ON u.id = f.user_id
		WHERE u.org_id = $1::uuid AND f.subject = 'u-402'`, org).Scan(&links); err != nil || links != 1 {
		t.Errorf("%d links for the Corporate SSO person (%v)", links, err)
	}
	if res.AttributesImported != 1 {
		t.Errorf("%d attributes imported, want costcenter", res.AttributesImported)
	}
	for _, want := range []string{
		"role admin of project Billing App is group Billing-App.admin", "a grant of role ghost of project Billing App",
		"gone-", "inactive in Zitadel", "locked (locked in Zitadel)", "ci-bot (a machine user",
		"administrative roles ORG_OWNER", "the subjects of 2 people", "nicknames and phone numbers of 1 people",
		"1 link(s) to IdP slug elsewhere", "metadata badge on 1",
		"OIDC application web of project Billing App (the export holds no client ID or secret",
		"https://billing.z.test/cb", "actions: 2", "loginPolicy: 1",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not say %q:\n%s", want, report)
		}
	}

	// Again: nothing is made twice.
	again, err := ImportZitadel(ctx, tx, org, exp, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if again.UsersCreated != 0 || again.GroupsCreated != 0 || again.Memberships != 0 || again.OTPImported != 0 ||
		again.LinksImported != 0 {
		t.Errorf("a second run did %+v", again.Result)
	}

	// The snake_case spelling protojson also reads, in an organisation of
	// its own; and an export of two organisations is refused, not merged.
	snake := strings.NewReplacer(`"humanUsers"`, `"human_users"`, `"userName"`, `"user_name"`, `"hashedPassword"`,
		`"hashed_password"`, `"projectRoles"`, `"project_roles"`, `"userGrants"`, `"user_grants"`, `"roleKey"`,
		`"role_key"`, `"roleKeys"`, `"role_keys"`, `"projectId"`, `"project_id"`, `"userId"`, `"user_id"`,
		fmt.Sprint(n), fmt.Sprint(n+1)).Replace(export)
	ctx2, tx2, org2 := importFixture(t)
	exp2, err := ParseZitadel(strings.NewReader(snake))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ImportZitadel(ctx2, tx2, org2, exp2, Options{Root: root})
	if err != nil || res2.UsersCreated != 1 || res2.Memberships != 1 {
		t.Errorf("the snake_case export: %d people, %d memberships (%v)", res2.UsersCreated, res2.Memberships, err)
	}
	two := `{"orgs":[{"orgId":"1"},{"orgId":"2"}]}`
	exp3, err := ParseZitadel(strings.NewReader(two))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportZitadel(ctx2, tx2, org2, exp3, Options{}); err == nil || !strings.Contains(err.Error(), "one at a time") {
		t.Errorf("an export of two organisations: %v", err)
	}
}
