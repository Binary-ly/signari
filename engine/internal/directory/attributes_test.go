package directory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

func attributeRoot(t *testing.T) *keys.RootKey {
	t.Helper()
	secret := make([]byte, 32)
	secret[0] = 9
	root, err := keys.NewRootKey("test", secret)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// mappedPeople is an organisation with two linked people and the attributes the
// tests below feed: department in the clear, employee_number personal, level a
// number and site required.
func mappedPeople(t *testing.T, pool *pgxpool.Pool) (orgID, sourceID string, remote []RemoteUser, user map[string]string) {
	t.Helper()
	ctx := context.Background()
	orgID, sourceID = fixture(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, a := range []store.Attribute{
		{Name: "department", DisplayName: "Department", ValueType: "string"},
		{Name: "employee_number", DisplayName: "Employee number", ValueType: "string", Personal: true},
		{Name: "level", DisplayName: "Level", ValueType: "number"},
		{Name: "site", DisplayName: "Site", ValueType: "string", Required: true},
	} {
		if _, err := store.DeclareAttribute(ctx, tx, orgID, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	suffix := rnd(t)
	remote = []RemoteUser{
		{ID: "a", Email: "ada-" + suffix + "@example.test", Name: "Ada"},
		{ID: "b", Email: "bea-" + suffix + "@example.test", Name: "Bea"},
	}
	if err := Apply(ctx, pool, sourceID, orgID, BuildPlan(remote, nil, "report", 20)); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `SELECT remote_id, user_id::text FROM core.directory_links WHERE source_id = $1::uuid`,
		sourceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	user = map[string]string{}
	for rows.Next() {
		var r, u string
		if err := rows.Scan(&r, &u); err != nil {
			t.Fatal(err)
		}
		user[r] = u
	}
	return orgID, sourceID, remote, user
}

var allFeeds = map[string]string{"departmentNumber": "department", "employeeNumber": "employee_number",
	"grade": "level", "l": "site"}

// A sync writes what the directory says, reads a sealed value back to compare it,
// so a second sync proposes nothing, and takes a value the directory dropped away.
func TestAMappedAttributeFollowsTheDirectory(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	root := attributeRoot(t)
	orgID, sourceID, remote, user := mappedPeople(t, pool)

	sync := func(want string) *attributePlan {
		t.Helper()
		p, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyAttributes(ctx, pool, root, sourceID, orgID, p); err != nil {
			t.Fatal(err)
		}
		if got := p.describe(); !strings.Contains(got, want) || (want == "" && got != "") {
			t.Fatalf("the report reads %q, want %q", got, want)
		}
		return p
	}

	remote[0].Attributes = map[string]string{"department": "Maths", "employee_number": "E1", "level": "3", "site": "Tripoli"}
	remote[1].Attributes = map[string]string{"department": "Physics", "employee_number": "E2", "level": "4", "site": "Benghazi"}
	sync("8 set, 0 cleared")

	var clear *string
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT a.value, a.value_sealed FROM core.user_attributes a
		JOIN core.user_attribute_schema s ON s.id = a.attribute_id
		WHERE a.user_id = $1::uuid AND s.name = 'employee_number'`, user["a"]).Scan(&clear, &sealed); err != nil {
		t.Fatal(err)
	}
	if clear != nil || len(sealed) == 0 {
		t.Fatalf("a personal attribute was not sealed: clear %v, %d sealed bytes", clear, len(sealed))
	}

	sync("") // Nothing changed, a sealed value included.

	remote[0].Attributes["employee_number"] = "E9"
	delete(remote[0].Attributes, "department")
	sync("1 set, 1 cleared")
	values, err := store.UserAttributeValues(ctx, pool, orgID, []string{"department", "employee_number", "level"},
		[]string{user["a"], user["b"]}, root)
	if err != nil {
		t.Fatal(err)
	}
	if values[user["a"]]["employee_number"] != "E9" || values[user["a"]]["department"] != "" ||
		values[user["b"]]["department"] != "Physics" || values[user["a"]]["level"] != "3" {
		t.Errorf("the values read %v", values)
	}
}

// A bind account that may not read an attribute looks like a company where nobody
// has one. Clearing everybody's on that evidence is the short-list failure.
func TestAnAttributeNobodyCarriesClearsNobody(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	root := attributeRoot(t)
	orgID, sourceID, remote, user := mappedPeople(t, pool)

	remote[0].Attributes = map[string]string{"department": "Maths"}
	first, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttributes(ctx, pool, root, sourceID, orgID, first); err != nil {
		t.Fatal(err)
	}

	remote[0].Attributes = nil
	p, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.clears) != 0 || !strings.Contains(p.describe(), "no entry carries what feeds department") {
		t.Fatalf("clears %v, report %q", p.clears, p.describe())
	}
	values, err := store.UserAttributeValues(ctx, pool, orgID, []string{"department"}, []string{user["a"]}, root)
	if err != nil {
		t.Fatal(err)
	}
	if values[user["a"]]["department"] != "Maths" {
		t.Errorf("the value went: %v", values)
	}
}

// One bad entry must not stop everybody else's sync, and PostgreSQL would refuse a
// whole statement over one value that is not text.
func TestAValueThatCannotBeHeldIsReportedAndLeftOut(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	root := attributeRoot(t)
	orgID, sourceID, remote, _ := mappedPeople(t, pool)

	remote[0].Attributes = map[string]string{"level": "senior", "department": "a\xffb", "site": "Tripoli"}
	remote[1].Attributes = map[string]string{"level": "2", "department": "x\x00y", "site": "Benghazi"}
	p, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttributes(ctx, pool, root, sourceID, orgID, p); err != nil {
		t.Fatal(err)
	}
	report := p.describe()
	if len(p.sets) != 3 || len(p.refused) != 3 || strings.Contains(report, "senior") ||
		!strings.Contains(report, "level of "+remote[0].Email) {
		t.Errorf("%d set, %d refused, reading %q", len(p.sets), len(p.refused), report)
	}

	// A required attribute the directory stopped holding for one person is kept.
	delete(remote[0].Attributes, "site")
	q, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.clears) != 0 || !strings.Contains(q.describe(), "required here") {
		t.Errorf("clears %v, report %q", q.clears, q.describe())
	}
}

// Whoever administers the directory is not thereby an administrator here.
func TestAPrivilegedPersonKeepsTheirValues(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	root := attributeRoot(t)
	orgID, sourceID, remote, user := mappedPeople(t, pool)

	var group string
	if err := pool.QueryRow(ctx, `INSERT INTO core.groups (org_id, name, display_name, may_impersonate)
		VALUES ($1::uuid, 'support', 'Support', true) RETURNING id::text`, orgID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core.group_members (group_id, user_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, group, user["a"], orgID); err != nil {
		t.Fatal(err)
	}
	remote[0].Attributes = map[string]string{"department": "Maths"}
	remote[1].Attributes = map[string]string{"department": "Physics"}
	p, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttributes(ctx, pool, root, sourceID, orgID, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.describe(), "1 privileged people left alone") {
		t.Errorf("the report reads %q", p.describe())
	}
	values, err := store.UserAttributeValues(ctx, pool, orgID, []string{"department"},
		[]string{user["a"], user["b"]}, root)
	if err != nil {
		t.Fatal(err)
	}
	if values[user["a"]]["department"] != "" || values[user["b"]]["department"] != "Physics" {
		t.Errorf("the values read %v", values)
	}
	var skipped int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM core.audit_events WHERE org_id = $1::uuid
		AND event_type = 'directory.privileged_skipped' AND subject_id = $2::uuid`, orgID, user["a"]).Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("%d records of it", skipped)
	}
}

// A paged fetch can return somebody twice, and one statement may not touch a row
// twice.
func TestAPersonListedTwiceHasTheLaterValue(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	root := attributeRoot(t)
	orgID, sourceID, remote, user := mappedPeople(t, pool)

	remote[0].Attributes = map[string]string{"employee_number": "E1", "department": "Maths"}
	remote[1].Attributes = map[string]string{"employee_number": "E2", "department": "Physics"}
	again := remote[0]
	again.Attributes = map[string]string{"employee_number": "E3", "department": "Music"}
	p, err := planAttributes(ctx, pool, root, sourceID, orgID, allFeeds, append(remote, again))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttributes(ctx, pool, root, sourceID, orgID, p); err != nil {
		t.Fatal(err)
	}
	values, err := store.UserAttributeValues(ctx, pool, orgID, []string{"department", "employee_number"},
		[]string{user["a"]}, root)
	if err != nil {
		t.Fatal(err)
	}
	if values[user["a"]]["employee_number"] != "E3" || values[user["a"]]["department"] != "Music" {
		t.Errorf("the values read %v", values)
	}
}

// A map is refused where it is set, not at the first sync that cannot use it.
func TestAMapIsCheckedWhenItIsSet(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	orgID, _, _, _ := mappedPeople(t, pool)
	root := attributeRoot(t)
	slug := "corp-" + rnd(t)
	if _, err := AddSource(ctx, pool, root, orgID, SourceSpec{Kind: "ldap", Slug: slug, LDAPURL: "ldaps://a.test",
		LDAPBaseDN: "dc=x", LDAPFlavour: "openldap", LDAPPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	var google string
	if err := pool.QueryRow(ctx, `SELECT slug FROM core.directory_sources WHERE org_id = $1::uuid AND kind = 'google'`,
		orgID).Scan(&google); err != nil {
		t.Fatal(err)
	}
	set := func(on string, m map[string]string) error {
		return ChangeSource(ctx, pool, orgID, on, SourceChange{AttributeMap: &m})
	}
	for name, tc := range map[string]struct {
		slug string
		m    map[string]string
		want string
	}{
		"undeclared":   {slug, map[string]string{"grade": "seniority"}, `no attribute "seniority"`},
		"not ldap":     {google, map[string]string{"grade": "level"}, "for an ldap source"},
		"all of them":  {slug, map[string]string{"*": "level"}, "not an LDAP attribute name"},
		"option":       {slug, map[string]string{"cert;binary": "level"}, "not an LDAP attribute name"},
		"feeds nought": {slug, map[string]string{"grade": ""}, "feeds nothing"},
		"two feed one": {slug, map[string]string{"grade": "level", "rank": "level"}, "both feed"},
	} {
		if err := set(tc.slug, tc.m); err == nil || !errors.Is(err, ErrSourceInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: answered %v", name, err)
		}
	}
	want := map[string]string{"grade": "level", "userPrincipalName": MapEmail, "displayName": MapName}
	if err := set(slug, want); err != nil {
		t.Fatal(err)
	}
	if err := ChangeSource(ctx, pool, orgID, slug, SourceChange{Enabled: new(bool)}); err != nil {
		t.Fatal(err)
	}
	settings, err := SourceSettingsOf(ctx, pool, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings[slug].AttributeMap) != 3 {
		t.Errorf("a change to something else left the map as %v", settings[slug].AttributeMap)
	}
	if err := set(slug, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if settings, _ = SourceSettingsOf(ctx, pool, orgID); len(settings[slug].AttributeMap) != 0 {
		t.Errorf("an empty map left %v", settings[slug].AttributeMap)
	}
}

// What a map names is asked for, read in whatever case the server answers with, and
// replaces where the flavour looks for an address and a name.
func TestAFetchReadsWhatTheMapNames(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{
		ldap.NewEntry("uid=ada,dc=x", map[string][]string{"entryUUID": {"u1"}, "mail": {"wrong@example.test"},
			"cn": {"Wrong"}, "userPrincipalName": {"ada@example.test"}, "preferredName": {"Ada L"},
			"employeenumber": {"E1", "E2"}}),
		ldap.NewEntry("uid=bea,dc=x", map[string][]string{"entryUUID": {"u2"}, "userPrincipalName": {"bea@example.test"}}),
	}}
	s := &LDAPSource{URL: "ldaps://a.test", BaseDN: "dc=x", Flavour: FlavourOpenLDAP,
		Dial:         func(context.Context, string) (ldapConn, error) { return f, nil },
		AttributeMap: map[string]string{"employeeNumber": "employee_number", "userPrincipalName": MapEmail, "preferredName": MapName}}
	got, err := s.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Email != "ada@example.test" || got[0].Name != "Ada L" || got[0].Attributes["employee_number"] != "E1" {
		t.Errorf("read %+v", got[0])
	}
	if got[1].Attributes != nil {
		t.Errorf("somebody with no value has %v", got[1].Attributes)
	}
	if _, ok := got[0].Attributes[MapEmail]; ok {
		t.Errorf("the address came through as an attribute: %v", got[0].Attributes)
	}
}
