package directory

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP stands in for a directory server. It exists to exercise the parts
// that decide whether a sync is safe: which attribute is treated as immutable,
// what happens when a search fails, and how each flavour reports a disabled
// account.
type fakeLDAP struct {
	entries   []*ldap.Entry
	searchErr error
	bindErr   error
	boundAs   string
	pageSize  uint32
}

func (f *fakeLDAP) Bind(u, p string) error { f.boundAs = u; return f.bindErr }

// UnauthenticatedBind records the anonymous case distinctly. The real client
// library refuses Bind("", "") outright, so a fake that accepts it hides the
// only bug this whole method exists to prevent.
func (f *fakeLDAP) UnauthenticatedBind(u string) error {
	f.boundAs = "<anonymous>"
	return f.bindErr
}
func (f *fakeLDAP) Close() error { return nil }
func (f *fakeLDAP) SearchWithPaging(_ *ldap.SearchRequest, pageSize uint32) (*ldap.SearchResult, error) {
	f.pageSize = pageSize
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func entry(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{
			Name: k, Values: v, ByteValues: toBytes(v),
		})
	}
	return e
}

func toBytes(v []string) [][]byte {
	out := make([][]byte, len(v))
	for i, s := range v {
		out[i] = []byte(s)
	}
	return out
}

func sourceWith(f *fakeLDAP, flavour LDAPFlavour) *LDAPSource {
	return &LDAPSource{
		URL: "ldap://fake", BaseDN: "dc=example,dc=test", Flavour: flavour,
		BindDN: "cn=sync,dc=example,dc=test", Password: "secret",
		Dial: func(context.Context, string) (ldapConn, error) { return f, nil },
	}
}

func TestOpenLDAPUsesEntryUUID(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{
		entry("uid=alice,dc=example,dc=test", map[string][]string{
			"uid": {"alice"}, "mail": {"alice@example.test"}, "cn": {"Alice"},
			"entryUUID": {"11111111-2222-3333-4444-555555555555"},
		}),
	}}
	got, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("fetched %d", len(got))
	}
	if got[0].ID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("ID = %q; a DN or email here would make a rename look like a "+
			"departure plus an arrival", got[0].ID)
	}
	if got[0].Email != "alice@example.test" || got[0].Name != "Alice" {
		t.Errorf("unexpected mapping: %+v", got[0])
	}
}

// TestActiveDirectoryUsesObjectGUID. objectGUID is binary; reading it as a
// string yields mojibake that changes with encoding, which is an unstable key
// dressed up as a stable one.
func TestActiveDirectoryUsesObjectGUID(t *testing.T) {
	guid := []byte{0x01, 0x02, 0x03, 0x04, 0xff, 0xfe, 0x00, 0x10,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x11, 0x22}
	e := &ldap.Entry{DN: "cn=Bob,ou=People,dc=corp,dc=test", Attributes: []*ldap.EntryAttribute{
		{Name: "sAMAccountName", Values: []string{"bob"}, ByteValues: [][]byte{[]byte("bob")}},
		{Name: "mail", Values: []string{"bob@corp.test"}, ByteValues: [][]byte{[]byte("bob@corp.test")}},
		{Name: "displayName", Values: []string{"Bob"}, ByteValues: [][]byte{[]byte("Bob")}},
		{Name: "objectGUID", Values: []string{string(guid)}, ByteValues: [][]byte{guid}},
		{Name: "userAccountControl", Values: []string{"512"}, ByteValues: [][]byte{[]byte("512")}},
	}}

	got, err := sourceWith(&fakeLDAP{entries: []*ldap.Entry{e}}, FlavourAD).
		Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != hex.EncodeToString(guid) {
		t.Errorf("ID = %q, want the hex of the raw GUID", got[0].ID)
	}
	if got[0].Suspended {
		t.Error("userAccountControl 512 is a normal enabled account")
	}
}

// TestActiveDirectoryDisabledBit. 0x2 is ACCOUNTDISABLE, and the other bits vary
// -- a substring test would be wrong for most accounts.
func TestActiveDirectoryDisabledBit(t *testing.T) {
	cases := map[string]bool{
		"512":   false, // normal account
		"514":   true,  // normal + disabled
		"66048": false, // normal + password never expires
		"66050": true,  // that, plus disabled
	}
	for uac, wantDisabled := range cases {
		e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{"x"}, ByteValues: [][]byte{{0x01}}},
			{Name: "sAMAccountName", Values: []string{"u"}, ByteValues: [][]byte{[]byte("u")}},
			{Name: "userAccountControl", Values: []string{uac}, ByteValues: [][]byte{[]byte(uac)}},
		}}
		got, err := sourceWith(&fakeLDAP{entries: []*ldap.Entry{e}}, FlavourAD).
			Fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Suspended != wantDisabled {
			t.Errorf("userAccountControl %s: suspended = %v, want %v",
				uac, got[0].Suspended, wantDisabled)
		}
	}
}

func TestFreeIPALock(t *testing.T) {
	e := entry("uid=carol,cn=users,dc=ipa,dc=test", map[string][]string{
		"uid": {"carol"}, "mail": {"carol@ipa.test"}, "displayName": {"Carol"},
		"ipaUniqueID": {"abc-123"}, "nsAccountLock": {"TRUE"},
	})
	got, err := sourceWith(&fakeLDAP{entries: []*ldap.Entry{e}}, FlavourFreeIPA).
		Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Suspended {
		t.Error("nsAccountLock TRUE was not read as locked")
	}
}

// TestASearchFailureIsAnError. The most dangerous bug available here: a failed
// search returning what was read so far looks exactly like a company where
// everybody left, and the reconciler is built to believe its input.
func TestASearchFailureIsAnError(t *testing.T) {
	f := &fakeLDAP{searchErr: errors.New("size limit exceeded")}
	got, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err == nil {
		t.Fatalf("a failed search returned %d entries and no error", len(got))
	}
	if got != nil {
		t.Error("a partial list came back alongside the error")
	}
}

// TestEntriesWithoutAnImmutableIDAreRefused. Falling back to the DN is the
// mistake that causes a mass lockout the day somebody reorganises an OU tree.
func TestEntriesWithoutAnImmutableIDAreRefused(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{
		entry("uid=a,dc=x", map[string][]string{"uid": {"a"}, "mail": {"a@x.test"}}),
	}}
	_, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err == nil {
		t.Fatal("entries with no entryUUID were imported anyway")
	}
	// And the message points at the likely cause rather than the symptom.
	if !strings.Contains(err.Error(), "objectGUID") {
		t.Errorf("the error should suggest the flavour is wrong; got %v", err)
	}
}

func TestPartialIDCoverageIsRefused(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{
		entry("uid=a,dc=x", map[string][]string{"uid": {"a"}, "entryUUID": {"u1"}}),
		entry("uid=b,dc=x", map[string][]string{"uid": {"b"}}),
	}}
	_, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err == nil {
		t.Fatal("a directory where only some entries are trackable was accepted")
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Errorf("the error should count them; got %v", err)
	}
}

func TestNoBaseDNIsRefused(t *testing.T) {
	s := sourceWith(&fakeLDAP{}, FlavourOpenLDAP)
	s.BaseDN = ""
	if _, err := s.Fetch(context.Background()); err == nil {
		t.Error("a search with no base DN was attempted")
	}
}

func TestBindFailureIsReported(t *testing.T) {
	f := &fakeLDAP{bindErr: errors.New("invalid credentials")}
	_, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err == nil {
		t.Fatal("a failed bind was ignored")
	}
	if !strings.Contains(err.Error(), "cn=sync") {
		t.Errorf("the error should name the bind DN; got %v", err)
	}
}

// TestPagingIsRequested. A plain search stops at the server's size limit and
// reports success -- silent truncation, which is the whole thing this avoids.
func TestPagingIsRequested(t *testing.T) {
	f := &fakeLDAP{}
	if _, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.pageSize == 0 {
		t.Error("the search was issued without paging")
	}
}

func TestMailFallsBackToUID(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{
		entry("uid=noemail,dc=x", map[string][]string{
			"uid": {"noemail"}, "entryUUID": {"u9"}, "cn": {"No Email"},
		}),
	}}
	got, err := sourceWith(f, FlavourOpenLDAP).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Email != "noemail" {
		t.Errorf("email = %q; an entry with no mail should fall back to uid rather "+
			"than importing an empty address", got[0].Email)
	}
}

// TestAnonymousBindUsesTheRightCall covers the bug a live server found.
//
// The first version called Bind("", ""), which the client library refuses before
// it reaches the wire -- so the anonymous path was documented, tested against a
// permissive fake, and could not connect to any real directory.
func TestAnonymousBindUsesTheRightCall(t *testing.T) {
	f := &fakeLDAP{entries: []*ldap.Entry{entry("uid=a,dc=x", map[string][]string{
		"uid": {"a"}, "mail": {"a@example.test"}, "cn": {"A"}, "entryUUID": {"u-1"},
	})}}
	s := &LDAPSource{
		BaseDN: "dc=x", Flavour: FlavourOpenLDAP,
		Dial: func(context.Context, string) (ldapConn, error) { return f, nil },
	}
	if _, err := s.Fetch(context.Background()); err != nil {
		t.Fatalf("anonymous fetch: %v", err)
	}
	if f.boundAs != "<anonymous>" {
		t.Fatalf("bound as %q, want the unauthenticated-bind call", f.boundAs)
	}
}

// TestBindDNWithoutPasswordIsRefused covers the trap that guard exists for.
//
// A DN with an empty password is an UNAUTHENTICATED bind: on most servers it
// succeeds and leaves the connection anonymous, so every later search reads
// whatever the directory publishes to strangers while looking authorised.
func TestBindDNWithoutPasswordIsRefused(t *testing.T) {
	f := &fakeLDAP{}
	s := &LDAPSource{
		BaseDN: "dc=x", BindDN: "cn=readonly,dc=x", Flavour: FlavourOpenLDAP,
		Dial: func(context.Context, string) (ldapConn, error) { return f, nil },
	}
	_, err := s.Fetch(context.Background())
	if err == nil {
		t.Fatal("a bind DN with no password was accepted")
	}
	if !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Fatalf("unhelpful error: %v", err)
	}
	if f.boundAs != "" {
		t.Fatalf("bound as %q; it should not have reached the wire", f.boundAs)
	}
}
