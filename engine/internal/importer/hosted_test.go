package importer

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// The three hosted services' exports (6.26), each a fixture shaped as its
// documentation describes (specs/exports/). None holds a password, so a person
// comes across only with a link: one the export names, to a provider registered
// here, or one to the service itself, kept as a provider here and named by -via.
// Everybody else is named and skipped, as is anybody turned off there; what is not
// carried is named.

func registerProvider(t *testing.T, ctx context.Context, tx pgx.Tx, org, slug string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `INSERT INTO core.identity_providers (org_id, slug, display_name, kind, client_id)
		VALUES ($1::uuid, $2, $2, 'oidc', 'c')`, org, slug); err != nil {
		t.Fatal(err)
	}
}

func linkedSubjects(t *testing.T, ctx context.Context, tx pgx.Tx, org, who string) []string {
	t.Helper()
	var subjects []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(f.subject ORDER BY f.subject), '{}')
		FROM core.federated_identities f JOIN core.users u ON u.id = f.user_id
		WHERE u.org_id = $1::uuid AND (u.username = $2 OR u.email = $2)`, org, who).Scan(&subjects); err != nil {
		t.Fatal(err)
	}
	return subjects
}

func reportOf(res *Result) string {
	return strings.Join(slices.Concat(res.Dropped, res.Renamed, res.UsersSkipped), "\n")
}

func wantReport(t *testing.T, report string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not say %q:\n%s", want, report)
		}
	}
}

func TestAnAuth0ExportImportsWhoALinkCarriesAndNamesTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeclareAttribute(ctx, tx, org, store.Attribute{Name: "costcenter", ValueType: "string"}); err != nil {
		t.Fatal(err)
	}
	google := fmt.Sprintf("google-%d", n)
	registerProvider(t, ctx, tx, org, google)
	// One person to a line (auth0-bulk-user-exports.txt:91-93), the profile's fields.
	export := fmt.Sprintf(`{"user_id":"auth0|ada1","email":"ada-%[1]d@a0.test","email_verified":true,"given_name":"Ada","family_name":"L","name":"Ada L","nickname":"al","identities":[{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"ada1","isSocial":false}],"user_metadata":{"costcenter":"cc-7","prefs":{"x":1}},"app_metadata":{"roles":["admin"]},"multifactor":["guardian"]}
{"user_id":"google-oauth2|1077","email":"bob-%[1]d@a0.test","email_verified":true,"name":"Bob","identities":[{"connection":"Google %[1]d","provider":"google-oauth2","user_id":"1077","isSocial":true}]}
{"user_id":"auth0|carol","email":"carol-%[1]d@a0.test","blocked":true,"identities":[{"connection":"Google %[1]d","provider":"google-oauth2","user_id":"2088"}]}
{"user_id":"auth0|dave","username":"dave-%[1]d","identities":[{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"dave"}]}
`, n)
	exp, err := ParseAuth0(strings.NewReader(export))
	if err != nil {
		t.Fatal(err)
	}

	// Without -via: only the person a link in the export carries.
	res, err := ImportAuth0(ctx, tx, org, exp, HostedOptions{Options: Options{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	report := reportOf(res)
	if res.UsersCreated != 1 || res.LinksImported != 1 {
		t.Errorf("without -via %d created, %d linked; want bob, by his Google identity:\n%s", res.UsersCreated,
			res.LinksImported, report)
	}
	if got := linkedSubjects(t, ctx, tx, org, fmt.Sprintf("bob-%d@a0.test", n)); len(got) != 1 || got[0] != "1077" {
		t.Errorf("bob is linked as %v", got)
	}
	wantReport(t, report, fmt.Sprintf("ada-%d@a0.test (no password comes out of Auth0", n),
		fmt.Sprintf("carol-%d@a0.test (blocked in Auth0)", n), "link(s) to username-password-authentication",
		"every password (Auth0's bulk export holds none")

	// With the service itself as a provider here: everyone not blocked, by user_id.
	via := fmt.Sprintf("auth0-%d", n)
	registerProvider(t, ctx, tx, org, via)
	res, err = ImportAuth0(ctx, tx, org, exp, HostedOptions{Options: Options{Root: root}, Via: via})
	if err != nil {
		t.Fatal(err)
	}
	report = reportOf(res)
	if res.UsersCreated != 2 || res.UsersUpdated != 1 || res.LinksImported != 3 {
		t.Errorf("with -via %d created, %d updated, %d linked; want ada and dave made, bob found, three links:\n%s",
			res.UsersCreated, res.UsersUpdated, res.LinksImported, report)
	}
	if got := linkedSubjects(t, ctx, tx, org, fmt.Sprintf("ada-%d@a0.test", n)); len(got) != 1 || got[0] != "auth0|ada1" {
		t.Errorf("ada is linked as %v", got)
	}
	var given, display string
	var verified bool
	if err := tx.QueryRow(ctx, `SELECT given_name, display_name, email_verified_at IS NOT NULL FROM core.users
		WHERE org_id = $1::uuid AND email = $2`, org, fmt.Sprintf("ada-%d@a0.test", n)).Scan(&given, &display,
		&verified); err != nil || given != "Ada" || display != "Ada L" || !verified {
		t.Errorf("ada is %q, %q, verified %v (%v)", given, display, verified, err)
	}
	if res.AttributesImported != 1 {
		t.Errorf("%d attributes imported, want costcenter", res.AttributesImported)
	}
	wantReport(t, report, "carol", "user_metadata prefs (not text) of 1 people", "app_metadata (it decided access there",
		"the second factors", "the nickname of 1 people", "the Auth0 identifiers of 3 people")

	again, err := ImportAuth0(ctx, tx, org, exp, HostedOptions{Options: Options{Root: root}, Via: via})
	if err != nil || again.UsersCreated != 0 || again.LinksImported != 0 {
		t.Errorf("a second run made %d people and %d links (%v)", again.UsersCreated, again.LinksImported, err)
	}
	if _, err := ImportAuth0(ctx, tx, org, exp, HostedOptions{Via: "nobody-here"}); err == nil ||
		!strings.Contains(err.Error(), "names no provider registered") {
		t.Errorf("-via naming no provider: %v", err)
	}
	if _, err := ParseAuth0(strings.NewReader("user_id,email\n'auth0|x','x@a0.test'\n")); err == nil ||
		!strings.Contains(err.Error(), "export the users as JSON") {
		t.Errorf("the CSV export: %v", err)
	}
}

func TestOktaUsersImportWhoAreNotTurnedOffAndNameTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	// Two pages of what the users API lists, one after another (okta-user-schemas.txt).
	pages := fmt.Sprintf(`[{"id":"00u1","status":"ACTIVE","profile":{"login":"ada-%[1]d@ok.test","email":"ada-%[1]d@ok.test","firstName":"Ada","lastName":"L","mobilePhone":"+15550100","title":"CTO"},"credentials":{"password":{},"provider":{"type":"OKTA","name":"OKTA"}}},
 {"id":"00u2","status":"SUSPENDED","profile":{"login":"sus-%[1]d@ok.test","email":"sus-%[1]d@ok.test"}}]
[{"id":"00u3","status":"STAGED","profile":{"login":"cy-%[1]d@ok.test","email":"cy-%[1]d@ok.test","displayName":"Cy"},"credentials":{"provider":{"type":"ACTIVE_DIRECTORY","name":"corp.example"}}},
 {"id":"00u4","status":"DEPROVISIONED","profile":{"login":"gone-%[1]d@ok.test"}}]`, n)
	exp, err := ParseOkta(strings.NewReader(pages))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportOkta(ctx, tx, org, exp, HostedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.UsersCreated != 0 || len(res.UsersSkipped) != 4 {
		t.Errorf("without -via %d created, %d skipped; want nobody, every password being withheld:\n%s",
			res.UsersCreated, len(res.UsersSkipped), reportOf(res))
	}
	via := fmt.Sprintf("okta-%d", n)
	registerProvider(t, ctx, tx, org, via)
	res, err = ImportOkta(ctx, tx, org, exp, HostedOptions{Via: via})
	if err != nil {
		t.Fatal(err)
	}
	report := reportOf(res)
	if res.UsersCreated != 2 || res.LinksImported != 2 {
		t.Errorf("with -via %d created, %d linked; want ada and cy:\n%s", res.UsersCreated, res.LinksImported, report)
	}
	if got := linkedSubjects(t, ctx, tx, org, fmt.Sprintf("ada-%d@ok.test", n)); len(got) != 1 || got[0] != "00u1" {
		t.Errorf("ada is linked as %v", got)
	}
	var username, given string
	var verified bool
	if err := tx.QueryRow(ctx, `SELECT username, given_name, email_verified_at IS NOT NULL FROM core.users
		WHERE org_id = $1::uuid AND email = $2`, org, fmt.Sprintf("ada-%d@ok.test", n)).Scan(&username, &given,
		&verified); err != nil || username != fmt.Sprintf("ada-%d@ok.test", n) || given != "Ada" || verified {
		t.Errorf("ada is %q, %q, verified %v (%v); nothing in a User says the address was confirmed", username,
			given, verified, err)
	}
	wantReport(t, report, "(suspended in Okta)", "(deactivated in Okta)", "profile.mobilePhone of 1 people",
		"profile.title of 1 people", "1 people sign in there against ACTIVE_DIRECTORY corp.example",
		"every password (Okta answers a password as {}")
	// Again, as imports are re-run: an Okta login is most often the address, so the
	// username and the address of the account found are the same text.
	again, err := ImportOkta(ctx, tx, org, exp, HostedOptions{Via: via})
	if err != nil {
		t.Fatalf("a second run: %v", err)
	}
	if again.UsersCreated != 0 || again.UsersUpdated != 2 || again.LinksImported != 0 {
		t.Errorf("a second run: %d created, %d updated, %d linked", again.UsersCreated, again.UsersUpdated,
			again.LinksImported)
	}
	for _, bad := range []string{`{"status":"ACTIVE","profile":{"login":"x"}}`, `{"id":"00u9"}`, `"text"`} {
		if _, err := ParseOkta(strings.NewReader(bad)); err == nil {
			t.Errorf("%s was read as Okta users", bad)
		}
	}
}

// Where the organisation has a migration source, people with no link come in
// pending, and the source checks each one's password at their first sign-in
// (docs/password-migration.md), so nobody sets a new one. The report says whether
// the source is enabled yet.
func TestPeopleComeInPendingWhereAMigrationSourceChecksTheirPassword(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	root, err := keys.NewRootKey("test", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMigrationSource(ctx, tx, root, org, store.MigrationSourceConfig{Kind: "oidc_password",
		DisplayName: "Old Okta", URL: "https://old.ok.test/oauth2/v1/token", ClientID: "migration",
		ClientSecret: "s3cret-for-the-test"}); err != nil {
		t.Fatal(err)
	}
	exp, err := ParseOkta(strings.NewReader(fmt.Sprintf(`{"id":"00u7","status":"ACTIVE","profile":{"login":"pat-%[1]d@ok.test","email":"pat-%[1]d@ok.test"}}
{"id":"00u8","status":"SUSPENDED","profile":{"login":"sam-%[1]d@ok.test","email":"sam-%[1]d@ok.test"}}`, n)))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportOkta(ctx, tx, org, exp, HostedOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.UsersCreated != 1 || res.LinksImported != 0 {
		t.Errorf("%d created, %d linked; want pat, pending and unlinked:\n%s", res.UsersCreated, res.LinksImported,
			reportOf(res))
	}
	var state string
	var passwords int
	if err := tx.QueryRow(ctx, `SELECT u.migration_state, (SELECT count(*) FROM core.password_credentials p
		WHERE p.user_id = u.id) FROM core.users u WHERE u.org_id = $1::uuid AND u.email = $2`, org,
		fmt.Sprintf("pat-%d@ok.test", n)).Scan(&state, &passwords); err != nil || state != "pending" || passwords != 0 {
		t.Errorf("pat is %q with %d passwords (%v); want pending with none, for the source to check", state,
			passwords, err)
	}
	wantReport(t, reportOf(res), "the passwords of 1 people (none comes out of Okta; they come in pending",
		"the migration source Old Okta", "it is disabled: test it", "(suspended in Okta)")
}

func TestAnEntraExportImportsKeepingTheObjectIDAndNamesTheRest(t *testing.T) {
	ctx, tx, org := importFixture(t)
	n := time.Now().UnixNano()
	via := fmt.Sprintf("entra-%d", n)
	registerProvider(t, ctx, tx, org, via)
	ada, guest, off := uuid.NewString(), uuid.NewString(), uuid.NewString()
	// The admin center's download, its columns as listed (entra-users-bulk-download.txt:59-84), with the mark
	// a spreadsheet leaves at the start.
	csvFile := "\xef\xbb\xbfuserPrincipalName,displayName,surname,mail,givenName,objectId,userType,jobTitle,department,accountEnabled\n" +
		fmt.Sprintf("ada-%[1]d@contoso.test,Ada L,L,ada-%[1]d@contoso.test,Ada,%[2]s,Member,CTO,,True\n", n, ada) +
		fmt.Sprintf("bob-%[1]d@contoso.test,Bob,,,,%[2]s,Member,,,False\n", n, off) +
		fmt.Sprintf("guest-%[1]d_x.test#EXT#@contoso.test,Guest,,guest-%[1]d@x.test,,%[2]s,Guest,,,True\n", n, guest)
	exp, err := ParseEntra(strings.NewReader(csvFile))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ImportEntra(ctx, tx, org, exp, HostedOptions{Via: via})
	if err != nil {
		t.Fatal(err)
	}
	report := reportOf(res)
	if res.UsersCreated != 2 || res.SubjectsKept != 2 || res.LinksImported != 2 {
		t.Errorf("%d created, %d keeping their object ID, %d linked; want ada and the guest:\n%s", res.UsersCreated,
			res.SubjectsKept, res.LinksImported, report)
	}
	var id, username string
	if err := tx.QueryRow(ctx, `SELECT id::text, username FROM core.users WHERE org_id = $1::uuid AND email = $2`, org,
		fmt.Sprintf("ada-%d@contoso.test", n)).Scan(&id, &username); err != nil || id != ada ||
		username != fmt.Sprintf("ada-%d@contoso.test", n) {
		t.Errorf("ada is %s, %q, want her object ID %s as her id (%v)", id, username, ada, err)
	}
	wantReport(t, report, fmt.Sprintf("bob-%d@contoso.test (disabled in Entra ID)", n), "jobTitle of 1 people",
		"1 of them are guests there", "every password (none is exported)")

	// Graph's user resources, in an organisation of its own.
	ctx2, tx2, org2 := importFixture(t)
	via2 := fmt.Sprintf("entra2-%d", n)
	registerProvider(t, ctx2, tx2, org2, via2)
	graph := fmt.Sprintf(`{"@odata.context":"x","value":[{"id":%q,"userPrincipalName":"cy-%d@contoso.test",
		"mail":null,"givenName":"Cy","surname":null,"displayName":"Cy","accountEnabled":true,"officeLocation":"9/1"}]}`,
		uuid.NewString(), n)
	exp2, err := ParseEntra(strings.NewReader(graph))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ImportEntra(ctx2, tx2, org2, exp2, HostedOptions{Via: via2})
	if err != nil || res2.UsersCreated != 1 || res2.SubjectsKept != 1 {
		t.Errorf("Graph's JSON: %d created, %d kept (%v):\n%s", res2.UsersCreated, res2.SubjectsKept, err, reportOf(res2))
	}
	wantReport(t, reportOf(res2), "officeLocation of 1 people")
	for bad, why := range map[string]string{
		`[{"id":"x","userPrincipalName":"y"}]`:                   "$select",
		"userPrincipalName,mail\nx@contoso.test,x\n":             "no objectid column",
		"userPrincipalName,objectId,accountEnabled\nx,y,maybe\n": "not True or False",
	} {
		if _, err := ParseEntra(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want it refused saying %s", bad, err, why)
		}
	}
}
