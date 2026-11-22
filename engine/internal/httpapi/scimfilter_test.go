package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// list asks a collection with a filter and returns the ids it found.
func (f *scimFixture) list(t *testing.T, collection, filter string) []string {
	t.Helper()
	status, body := f.do(t, http.MethodGet, "/scim/v2/"+collection+"?filter="+url.QueryEscape(filter), "")
	if status != http.StatusOK {
		t.Fatalf("%s answered %d: %v", filter, status, body)
	}
	resources, _ := body["Resources"].([]any)
	ids := []string{}
	for _, r := range resources {
		ids = append(ids, r.(map[string]any)["id"].(string))
	}
	// The count is of what matched, not of the collection: an upstream reads
	// totalResults to decide whether somebody exists.
	if total, _ := body["totalResults"].(float64); int(total) != len(ids) {
		t.Errorf("%s: totalResults is %v, of %d resources", filter, total, len(ids))
	}
	slices.Sort(ids)
	return ids
}

// scimPerson provisions somebody with what the filters ask about, returning
// their resource id.
func (f *scimFixture) scimPerson(t *testing.T, externalID, userName, displayName, email string, active bool) string {
	t.Helper()
	emails := ""
	if email != "" {
		emails = fmt.Sprintf(`,"emails":[{"value":%q,"primary":true}]`, email)
	}
	status, body := f.do(t, http.MethodPost, "/scim/v2/Users", fmt.Sprintf(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":%q,"userName":%q,
		  "displayName":%q,"active":%v%s}`, externalID, userName, displayName, active, emails))
	if status != http.StatusCreated {
		t.Fatalf("provisioning %s gave %d: %v", userName, status, body)
	}
	return body["id"].(string)
}

type filterCase struct {
	filter string
	want   []string
}

func (f *scimFixture) expect(t *testing.T, collection string, cases []filterCase) {
	t.Helper()
	for _, c := range cases {
		want := slices.Clone(c.want)
		slices.Sort(want)
		if want == nil {
			want = []string{}
		}
		if got := f.list(t, collection, c.filter); !slices.Equal(got, want) {
			t.Errorf("%s\n found %v\n want  %v", c.filter, got, want)
		}
	}
}

// The row (7.10): `externalId eq`, and `and` and `or`, with the rest of Table 3
// over what the resources return. Each case has an answer that a filter ignored,
// or read as anything else, would get wrong.
func TestAListFilterAsksWhatTheGrammarSays(t *testing.T) {
	f := newSCIMFixture(t)
	run := fmt.Sprint(time.Now().UnixNano())
	ada := f.scimPerson(t, "Ext-Ada-"+run, "ada-"+run+"@example.test", "Ada Lovelace", "ada-"+run+"@mail.test", true)
	grace := f.scimPerson(t, "ext-grace-"+run, "grace-"+run+"@example.test", "Grace 100% Hopper", "grace-"+run+"@mail.test", true)
	// A userName with no @, which would otherwise become the address.
	alan := f.scimPerson(t, "ext-alan-"+run, "alan-"+run, "Alan_Turing", "", false)
	mine := ` and userName co "` + run + `"`

	f.expect(t, "Users", []filterCase{
		// The row's own: an upstream's identifier is matched as stored.
		{`externalId eq "Ext-Ada-` + run + `"`, []string{ada}},
		{`externalId eq "ext-ada-` + run + `"`, nil},
		{`userName eq "ADA-` + run + `@EXAMPLE.TEST"`, []string{ada}},
		{`userName eq "ada-` + run + `@example.test" or externalId eq "ext-alan-` + run + `"`, []string{ada, alan}},
		{`userName sw "ada-` + run + `" and displayName sw "Grace"`, nil},
		{`displayName co "Grace"` + mine, []string{grace}},

		// And binds tighter than or, not tighter than both, and brackets undo it.
		{`externalId eq "ext-alan-` + run + `" or userName co "` + run + `" and active eq false`, []string{alan}},
		{`(externalId eq "ext-alan-` + run + `" or userName sw "ada-` + run + `") and active eq true`, []string{ada}},
		{`not (externalId eq "ext-alan-` + run + `")` + mine, []string{ada, grace}},

		// A value is text: neither of these is a wildcard.
		{`displayName co "100%"` + mine, []string{grace}},
		{`displayName co "100_"` + mine, nil},
		{`displayName sw "alan_"` + mine, []string{alan}},
		{`displayName sw "alan%"` + mine, nil},
		{`displayName ew "LOVELACE"` + mine, []string{ada}},

		// An address only some have. Somebody with none is not equal to one, and
		// `not` keeps them: a NULL would have dropped them from both.
		{`emails.value eq "ADA-` + run + `@MAIL.TEST"`, []string{ada}},
		{`emails.value ne "ada-` + run + `@mail.test"` + mine, []string{grace, alan}},
		{`not (emails.value eq "ada-` + run + `@mail.test")` + mine, []string{grace, alan}},
		{`emails pr` + mine, []string{ada, grace}},
		{`emails.value pr` + mine, []string{ada, grace}},
		{`not (emails pr)` + mine, []string{alan}},
		{`emails.value eq null` + mine, []string{alan}},

		{`active eq true` + mine, []string{ada, grace}},
		{`active ne true` + mine, []string{alan}},
		{`active eq false` + mine, []string{alan}},

		// By the id this server issued, in any spelling, and an id of nothing is
		// nobody rather than a mistake.
		{`id eq "` + ada + `"`, []string{ada}},
		{`id eq "` + strings.ToUpper(ada) + `"`, []string{ada}},
		{`id eq "not-one-of-ours"`, nil},
		{`id ne "` + ada + `"` + mine, []string{grace, alan}},

		// Lexicographical, and with the schema written out.
		{`userName gt "grace-` + run + `@example.test"` + mine, nil},
		{`userName ge "grace-` + run + `@example.test"` + mine, []string{grace}},
		{`userName le "ada-` + run + `@example.test"` + mine, []string{ada}},
		{`userName lt "ada-` + run + `@example.test"` + mine, nil},
		{`urn:ietf:params:scim:schemas:core:2.0:User:externalId eq "Ext-Ada-` + run + `"`, []string{ada}},

		// A value is a value, whatever it looks like.
		{`userName eq "' OR '1'='1"`, nil},
		{`userName eq "x\" or active eq true or userName eq \"y"`, nil},
		{"displayName eq \"\x5cu0041da Lovelace\"" + mine, []string{ada}},
	})
}

// A time compares as the resource shows it: to the second, chronologically.
func TestAListFilterComparesTimes(t *testing.T) {
	f := newSCIMFixture(t)
	_, id := f.provisionUser(t, "times")
	status, body := f.do(t, http.MethodGet, "/scim/v2/Users/"+id, "")
	if status != http.StatusOK {
		t.Fatalf("read %d", status)
	}
	shown := body["meta"].(map[string]any)["lastModified"].(string)
	at, err := time.Parse(time.RFC3339, shown)
	if err != nil {
		t.Fatal(err)
	}
	before, after := at.Add(-time.Hour).Format(time.RFC3339), at.Add(time.Hour).Format(time.RFC3339)
	mine := ` and id eq "` + id + `"`
	found, none := []string{id}, []string(nil)
	f.expect(t, "Users", []filterCase{
		{`meta.lastModified eq "` + shown + `"` + mine, found},
		{`meta.lastModified ne "` + shown + `"` + mine, none},
		{`meta.lastModified ge "` + shown + `"` + mine, found},
		{`meta.lastModified gt "` + shown + `"` + mine, none},
		{`meta.lastModified gt "` + before + `"` + mine, found},
		{`meta.lastModified lt "` + after + `"` + mine, found},
		{`meta.lastModified lt "` + before + `"` + mine, none},
		{`meta.created le "` + after + `"` + mine, found},
	})
}

func TestAGroupListFilterAsksWhatAGroupHas(t *testing.T) {
	f := newSCIMFixture(t)
	run := fmt.Sprint(time.Now().UnixNano())
	_, member := f.provisionUser(t, "member")
	_, stranger := f.provisionUser(t, "stranger")
	alpha := f.createGroup(t, "Alpha Team "+run, member)
	beta := f.createGroup(t, "Beta Team "+run)
	mine := ` and displayName co "` + run + `"`

	f.expect(t, "Groups", []filterCase{
		// /Schemas says a group's name does not depend on case.
		{`displayName eq "alpha team ` + run + `"`, []string{alpha}},
		{`(displayName sw "alpha" or displayName sw "beta")` + mine, []string{alpha, beta}},
		{`members pr` + mine, []string{alpha}},
		{`not (members pr)` + mine, []string{beta}},
		{`members.value pr` + mine, []string{alpha}},
		{`members.value eq "` + member + `"` + mine, []string{alpha}},
		{`members.value eq "` + stranger + `"` + mine, nil},
		{`members.value eq "nobody"` + mine, nil},
		{`id eq "` + beta + `"`, []string{beta}},
	})

	// An identifier as an upstream set it, matched as stored.
	status, body := f.do(t, http.MethodPost, "/scim/v2/Groups",
		`{"displayName":"Ext `+run+`","externalId":"Ext-`+run+`"}`)
	if status != http.StatusCreated {
		t.Fatalf("creating gave %d: %v", status, body)
	}
	f.expect(t, "Groups", []filterCase{
		{`externalId eq "Ext-` + run + `"`, []string{body["id"].(string)}},
		{`externalId eq "ext-` + run + `"`, nil},
	})
}

// Anything that cannot be answered is said so, never answered with the
// collection: an upstream reading the first result matches the wrong person.
func TestAFilterThatCannotBeAnsweredIsRefused(t *testing.T) {
	f := newSCIMFixture(t)
	for collection, filters := range map[string][]string{
		"Users": {
			// What is not stored, alone, negated, and as one term of many: read
			// as absent, the second of these matches everybody.
			`nickName eq "a"`,
			`name.givenName eq "a"`,
			`not (nickName eq "a")`,
			`userName eq "a" or foo pr`,
			// RFC 7644's own example of an operator to refuse.
			`userName regex "a"`,
			// Table 3 says so of a Boolean.
			`active gt true`,
			`active co "t"`,
			// A value of the wrong type is not a value to convert.
			`active eq "true"`,
			`userName eq 5`,
			`userName eq true`,
			`meta.created eq "yesterday"`,
			`meta.created co "2026"`,
			`id gt "a"`,
			// A complex attribute needs a sub-attribute (specs/rfc7644.txt:1197).
			`emails eq "a@b.test"`,
			`emails.primary eq true`,
			// Grammar this server does not answer, and not its own schema.
			`emails[type eq "work"]`,
			`userName eq bjensen`,
			`urn:example:Other:userName eq "a"`,
		},
		"Groups": {
			`userName eq "a"`,
			`active eq true`,
			`members eq "a"`,
			`members.value co "a"`,
			`members.value ne "a"`,
			`members.display eq "a"`,
		},
	} {
		for _, filter := range filters {
			status, body := f.do(t, http.MethodGet, "/scim/v2/"+collection+"?filter="+url.QueryEscape(filter), "")
			if status != http.StatusBadRequest || body["scimType"] != "invalidFilter" {
				t.Errorf("%s %s answered %d %v, want 400 invalidFilter", collection, filter, status, body)
			}
		}
	}
}

// Asked of each attribute /Schemas publishes, which is how a client learns what
// to ask: an attribute there that a filter refuses is a promise broken.
func TestEveryPublishedAttributeCanBeFiltered(t *testing.T) {
	f := newSCIMFixture(t)
	// Sub-attributes that are not asked about, and why.
	unasked := map[string]string{
		"emails.primary":  "always true of the one address, so the address is what there is to ask",
		"members.display": "the member's name, which the id they are asked about already decides",
		"members.$ref":    "the same id as a URL",
	}
	collection := map[string]string{"User": "Users", "Group": "Groups"}
	asked := 0
	for _, def := range scimSchemaDefinitions() {
		for _, a := range def["attributes"].([]map[string]any) {
			name := a["name"].(string)
			paths := []string{name}
			if subs, ok := a["subAttributes"].([]map[string]any); ok {
				for _, s := range subs {
					paths = append(paths, name+"."+s["name"].(string))
				}
			}
			for _, path := range paths {
				if _, skip := unasked[path]; skip {
					continue
				}
				asked++
				status, body := f.do(t, http.MethodGet, "/scim/v2/"+collection[def["name"].(string)]+"?filter="+
					url.QueryEscape(path+" pr"), "")
				if status != http.StatusOK {
					t.Errorf("%s pr answered %d %v", path, status, body)
				}
			}
		}
	}
	if asked < 8 {
		t.Fatalf("only %d attributes were asked about: the walk is wrong", asked)
	}
}

// /Schemas says what a filter does (specs/rfc7644.txt:1216), so the two are read
// together: it declared externalId case-insensitive while the engine matched it
// as stored, and a client reading one was told the wrong thing about the other.
func TestAFilterDoesWhatTheSchemaDeclares(t *testing.T) {
	f := newSCIMFixture(t)
	run := fmt.Sprint(time.Now().UnixNano())
	user := map[string]any{"externalId": "Ext-" + run, "userName": "Name-" + run, "displayName": "Shown-" + run}
	id := f.scimPerson(t, user["externalId"].(string), user["userName"].(string), user["displayName"].(string), "", true)
	group := map[string]any{"externalId": "Ext-Group-" + run, "displayName": "Shown-Group-" + run}
	status, body := f.do(t, http.MethodPost, "/scim/v2/Groups",
		fmt.Sprintf(`{"displayName":%q,"externalId":%q}`, group["displayName"], group["externalId"]))
	if status != http.StatusCreated {
		t.Fatalf("creating gave %d: %v", status, body)
	}
	resources := map[string]struct {
		collection, id string
		values         map[string]any
	}{
		"User":  {"Users", id, user},
		"Group": {"Groups", body["id"].(string), group},
	}
	asked := 0
	for _, def := range scimSchemaDefinitions() {
		r := resources[def["name"].(string)]
		for _, a := range def["attributes"].([]map[string]any) {
			value, ok := r.values[a["name"].(string)].(string)
			if !ok {
				continue
			}
			asked++
			filter := fmt.Sprintf(`%s eq %q`, a["name"], strings.ToUpper(value))
			got := f.list(t, r.collection, filter)
			if exact := a["caseExact"].(bool); exact == slices.Contains(got, r.id) {
				t.Errorf("%s: caseExact is %v in /Schemas, and %s found %v", a["name"], exact, filter, got)
			}
			if got := f.list(t, r.collection, fmt.Sprintf(`%s eq %q`, a["name"], value)); !slices.Contains(got, r.id) {
				t.Errorf("%s as it was stored found %v", a["name"], got)
			}
		}
	}
	if asked != 5 {
		t.Fatalf("%d attributes compared, want 5: the walk is wrong", asked)
	}
}

// An upstream asks `userName eq` before every create, so a scan here is a scan
// per person in a sync. The conditions are the ones scimFilterSQL writes.
func TestAnEqualityFilterUsesAnIndex(t *testing.T) {
	f := newSCIMFixture(t)
	f.provisionUser(t, "plan")
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	for _, cond := range []string{
		`lower(l.user_name) = lower('x'::text)`,
		`l.external_id = 'x'::text`,
		`l.resource_id = '00000000-0000-0000-0000-000000000000'::uuid`,
	} {
		rows, err := tx.Query(ctx, `EXPLAIN SELECT 1 FROM core.scim_source_links l
			WHERE l.source_id = '`+f.srcID+`'::uuid AND `+cond)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		rows.Close()
		if strings.Contains(plan.String(), "Seq Scan") {
			t.Errorf("%s scans:\n%s", cond, plan.String())
		}
	}
}
