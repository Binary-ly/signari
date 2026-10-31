package ldapd

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapclient "github.com/go-ldap/ldap/v3"
)

// nameDir is a small directory of names picked to trip a substring match.
type nameDir struct {
	fakeAuth
	people []*Identity
}

func (d *nameDir) List(context.Context, Query) ([]*Identity, error) { return d.people, nil }
func (d *nameDir) Lookup(context.Context, string) (*Identity, error) {
	return nil, nil
}

func newNameDir() *nameDir {
	person := func(uid, name, mail string) *Identity {
		return &Identity{Username: uid, DisplayName: name, Email: mail, Active: true}
	}
	return &nameDir{people: []*Identity{
		person("ada", "Ada Lovelace", "ada@example.test"),
		person("alan", "Alan Turing", "alan@other.test"),
		person("grace", "Grace Hopper", ""),
		person("star", "a*b c", "star@example.test"),
		person("plain", "axb c", "plain@example.test"),
		person("overlap", "aba", "overlap@example.test"),
	}}
}

// Each filter a client can write, through a real client's encoding of it, and
// who it finds. New kinds are evaluated on the parts the BER carried, so a
// value's own `*`, written \2a, is a character and not a wildcard.
func TestEveryKindOfFilterFindsWhoItShould(t *testing.T) {
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, newNameDir()))
	for filter, want := range map[string]string{
		// Substrings: an initial, a final, anything between, in order.
		"(cn=al*)":              "alan",
		"(cn=*Hopper)":          "grace",
		"(cn=*love*)":           "ada",
		"(cn=A*L*e)":            "ada",
		"(mail=*@example.test)": "ada overlap plain star",
		// The parts may not overlap: "aba" holds "ab" and "ba" only by sharing.
		"(cn=ab*ba)": "",
		// A value's own star is a character.
		`(cn=a\2ab*)`: "star",
		`(cn=a*b c)`:  "plain star",
		// Ordering, case aside.
		"(uid>=star)": "star",
		"(uid<=ada)":  "ada",
		// Approximately: treated as equality, as the RFC says when it is not
		// supported.
		"(cn~=ada lovelace)": "ada",
		// Extensible, by name.
		"(cn:caseExactMatch:=Ada Lovelace)":   "ada",
		"(cn:caseExactMatch:=ada lovelace)":   "",
		"(cn:caseIgnoreMatch:=ada lovelace)":  "ada",
		"(:caseIgnoreMatch:=alan@other.test)": "alan",
		"(uid:dn:=ada)":                       "ada",
		"(dc:dn:=example)":                    "ada alan grace overlap plain star",
		// A rule not recognised is Undefined, not an error (:1419).
		"(cn:1.2.3.4:=ada)": "",
		// The mail of nobody, and of somebody without one.
		"(!(mail=*))": "grace",
	} {
		res, err := c.Search(anonymousSearch(filter, 0))
		if err != nil {
			t.Errorf("%s: %v", filter, err)
			continue
		}
		var got []string
		for _, e := range res.Entries {
			got = append(got, e.GetAttributeValue("uid"))
		}
		sort.Strings(got)
		if strings.Join(got, " ") != want {
			t.Errorf("%s found %q, want %q", filter, strings.Join(got, " "), want)
		}
	}
}

// The search returned nobody for what it could not evaluate only until a NOT
// was put round it: FALSE negates, and `(!(shoeSize=12))` was the whole
// directory. Undefined stays Undefined through a NOT (specs/rfc4511.txt:1278),
// and only a filter that is TRUE returns an entry (:1268).
func TestWhatCannotBeEvaluatedIsNeverNegatedIntoEverybody(t *testing.T) {
	dir := newNameDir()
	c := dial(t, startServerWith(t, Config{AllowAnonymousSearch: true}, dir))
	everybody := len(dir.people)
	for filter, want := range map[string]int{
		"(shoeSize=12)":                           0,
		"(!(shoeSize=12))":                        0,
		"(!(shoeSize=*))":                         0,
		"(!(shoeSize>=12))":                       0,
		"(!(shoeSize=a*))":                        0,
		"(!(cn:1.2.3.4:=ada))":                    0,
		"(!(!(shoeSize=12)))":                     0,
		"(&(!(shoeSize=12))(objectClass=person))": 0,
		// An OR needs only one TRUE arm, and an AND one FALSE.
		"(|(shoeSize=12)(uid=ada))":  1,
		"(!(&(shoeSize=12)(uid=x)))": everybody,
		"(!(|(shoeSize=12)(uid=x)))": 0,
		// An attribute this directory knows and an entry lacks is FALSE, so its
		// NOT is an answer.
		"(!(cn=nobody))": everybody,
	} {
		res, err := c.Search(anonymousSearch(filter, 0))
		if err != nil {
			t.Errorf("%s: %v", filter, err)
			continue
		}
		if len(res.Entries) != want {
			t.Errorf("%s found %d entries, want %d", filter, len(res.Entries), want)
		}
	}
}

// A substrings filter breaking its own grammar, or past the cap, is Undefined.
// specs/rfc4511.txt:1312: not an error.
func TestABadSubstringsFilterIsUndefined(t *testing.T) {
	for name, parts := range map[string][]struct {
		tag   uint64
		value string
	}{
		"final before the end":     {{2, "a"}, {1, "b"}},
		"initial after the start":  {{1, "a"}, {0, "b"}},
		"two initials":             {{0, "a"}, {0, "b"}},
		"empty part":               {{0, ""}},
		"a part of no known kind":  {{9, "a"}},
		"nine parts, past the cap": {{1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}, {1, "a"}},
	} {
		f, err := decodeFilter(substringPacket(parts))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.Kind != filterUnsupported {
			t.Errorf("%s decoded to %+v", name, f)
		}
	}
}

// substringPacket is a SubstringFilter on cn with these parts, as a client that
// breaks the grammar would write it.
func substringPacket(parts []struct {
	tag   uint64
	value string
}) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, filterTagSubstring, nil, "substrings")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "type"))
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "substrings")
	for _, part := range parts {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(part.tag), part.value, "part"))
	}
	p.AppendChild(seq)
	return p
}

// The directory says what it is: the root DSE names the subschema entry, and
// that entry defines every attribute and class an entry here can hold, before
// any bind, as a client reading it to decide how to bind needs.
func TestTheSubschemaDefinesEverythingAnEntryHolds(t *testing.T) {
	c := dial(t, startServerWith(t, Config{}, newNameDir()))
	root, err := c.Search(ldapclient.NewSearchRequest("", ldapclient.ScopeBaseObject, ldapclient.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"subschemaSubentry"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	dn := root.Entries[0].GetAttributeValue("subschemaSubentry")
	if dn != subschemaDN {
		t.Fatalf("the root DSE names %q", dn)
	}
	read := func(attrs ...string) *ldapclient.Entry {
		t.Helper()
		res, err := c.Search(ldapclient.NewSearchRequest(dn, ldapclient.ScopeBaseObject, ldapclient.NeverDerefAliases,
			0, 0, false, "(objectClass=subschema)", attrs, nil))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("the subschema entry answered %d entries", len(res.Entries))
		}
		return res.Entries[0]
	}
	e := read("attributeTypes", "objectClasses", "ldapSyntaxes")
	types := strings.Join(e.GetAttributeValues("attributeTypes"), "\n")
	for _, a := range schema {
		if !strings.Contains(types, "'"+a.Name+"'") {
			t.Errorf("%s is in the schema and not in the subschema", a.Name)
		}
		def := definitionOf(e.GetAttributeValues("attributeTypes"), a.Name)
		if a.Single && !strings.Contains(def, "SINGLE-VALUE") {
			t.Errorf("%s holds one value here, and its definition says otherwise: %s", a.Name, def)
		}
	}
	classes := strings.Join(e.GetAttributeValues("objectClasses"), "\n")
	for _, class := range objectClasses {
		if !strings.Contains(classes, "'"+class+"'") {
			t.Errorf("the class %s is not in the subschema", class)
		}
	}
	syntaxes := strings.Join(e.GetAttributeValues("ldapSyntaxes"), "\n")
	for _, def := range append(append([]string{}, subschemaAttributeTypes...), subschemaObjectClasses...) {
		if strings.Count(def, "(") != strings.Count(def, ")") {
			t.Errorf("an unbalanced definition: %s", def)
		}
		if _, after, ok := strings.Cut(def, "SYNTAX "); ok {
			oid, _, _ := strings.Cut(strings.Fields(after)[0], "{")
			if !strings.Contains(syntaxes, oid) {
				t.Errorf("%s names a syntax the entry does not define", def)
			}
		}
	}
	if got := read("+").GetAttributeValues("objectClasses"); len(got) == 0 {
		t.Error("`+` did not return the operational attributes")
	}
}

func definitionOf(defs []string, name string) string {
	for _, d := range defs {
		if strings.Contains(d, "'"+name+"'") {
			return d
		}
	}
	return ""
}

func TestAPrefixIsAskedOfTheDatabase(t *testing.T) {
	s := New(Config{BaseDN: baseDN}, &fakeAuth{}, nil)
	for text, want := range map[string]*Condition{
		"(uid=al*)":   {Op: CondLoginPrefix, Value: "al"},
		"(mail=ada*)": {Op: CondMailPrefix, Value: "ada"},
		"(uid=al*n)":  {Op: CondLoginPrefix, Value: "al"},
		"(uid~=ada)":  {Op: CondLogin, Value: "ada"},
		"(cn=al*)":    nil, // a name has a fallback no index reads
		"(uid=*an)":   nil,
		"(uid>=a)":    nil,
	} {
		if got := s.narrow(filterOf(t, text)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s reduced to %+v, want %+v", text, got, want)
		}
	}
}
