package importer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Importing from Microsoft Entra ID (6.26).
//
// Two files are read. The admin center's "Download users" CSV, whose columns are
// the attributes it lists (specs/exports/entra-users-bulk-download.txt:59-84, read
// 5 November 2026); the preview download, whose columns follow whatever the list
// view shows (:99-104), is not, unless its columns carry those names. And Graph
// user resources as JSON (specs/exports/msgraph-user-resource.txt, its
// properties cited by line below): an array of them, or an object holding the
// array under "value".
//
// No password is in either. A person's object ID is a UUID, which an id here is,
// so an account made here takes it as its own and keeps it.

// entraColumns are the classic download's (:59-84) that this reads, folded to
// lower case.
var entraColumns = []string{"userprincipalname", "mail", "givenname", "surname", "displayname", "objectid",
	"accountenabled", "usertype"}

type entraUser struct {
	ID                string `json:"id"`                // :1131-1134
	UserPrincipalName string `json:"userPrincipalName"` // :2010
	Mail              string `json:"mail"`              // :1263
	GivenName         string `json:"givenName"`         // :1095
	Surname           string `json:"surname"`           // :1954
	DisplayName       string `json:"displayName"`       // :869
	// :533-540. A pointer, because it comes only when asked for, and a person
	// listed without it may be disabled there.
	AccountEnabled *bool  `json:"accountEnabled"`
	UserType       string `json:"userType"` // :2052, Member or Guest
	rest           []string
}

// EntraExport is a parsed export.
type EntraExport struct{ users []entraUser }

// ParseEntra reads the CSV download or Graph's JSON.
func ParseEntra(r io.Reader) (*EntraExport, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(512)
	head = bytes.TrimPrefix(bytes.TrimSpace(head), []byte("\xef\xbb\xbf"))
	var exp *EntraExport
	var err error
	if len(head) > 0 && (head[0] == '[' || head[0] == '{') {
		exp, err = parseEntraJSON(br)
	} else {
		exp, err = parseEntraCSV(br)
	}
	if err != nil {
		return nil, err
	}
	if len(exp.users) == 0 {
		return nil, fmt.Errorf("importer: the Entra export holds nobody")
	}
	return exp, nil
}

func parseEntraJSON(r io.Reader) (*EntraExport, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("importer: reading the Entra users: %w", err)
	}
	var list []map[string]json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		var page struct {
			Value []map[string]json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &page); err != nil || page.Value == nil {
			return nil, fmt.Errorf("importer: the Entra JSON is neither a list of users nor an object holding one " +
				"under value")
		}
		list = page.Value
	}
	read := map[string]bool{"id": true, "userPrincipalName": true, "mail": true, "givenName": true, "surname": true,
		"displayName": true, "accountEnabled": true, "userType": true}
	exp := &EntraExport{}
	for i, fields := range list {
		body, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		var u entraUser
		if err := json.Unmarshal(body, &u); err != nil {
			return nil, fmt.Errorf("importer: user %d of the Entra JSON: %w", i+1, err)
		}
		if u.AccountEnabled == nil {
			return nil, fmt.Errorf("importer: user %d was listed without accountEnabled, which Graph sends only "+
				"when asked for; list the users again with $select naming it, so that nobody disabled there is "+
				"enabled here", i+1)
		}
		for _, k := range sortedKeys(fields) {
			if !read[k] && !strings.HasPrefix(k, "@") && zitadelCount(fields[k]) > 0 {
				u.rest = append(u.rest, k)
			}
		}
		exp.users = append(exp.users, u)
	}
	return exp, nil
}

func parseEntraCSV(r io.Reader) (*EntraExport, error) {
	c := csv.NewReader(r)
	c.FieldsPerRecord = -1
	header, err := c.Read()
	if err != nil {
		return nil, fmt.Errorf("importer: reading the Entra CSV: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\xef\xbb\xbf")))] = i
	}
	for _, need := range []string{"userprincipalname", "objectid", "accountenabled"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("importer: the Entra CSV has no %s column; this reads the admin center's "+
				"\"Download users\" file, whose columns include userPrincipalName, objectId and accountEnabled", need)
		}
	}
	exp := &EntraExport{}
	for n := 2; ; n++ {
		rec, err := c.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("importer: line %d of the Entra CSV: %w", n, err)
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		enabled := strings.EqualFold(get("accountenabled"), "true")
		if !enabled && !strings.EqualFold(get("accountenabled"), "false") {
			return nil, fmt.Errorf("importer: line %d of the Entra CSV says accountEnabled is %q, not True or "+
				"False", n, get("accountenabled"))
		}
		u := entraUser{ID: strings.ToLower(get("objectid")), UserPrincipalName: get("userprincipalname"),
			Mail: get("mail"), GivenName: get("givenname"), Surname: get("surname"), DisplayName: get("displayname"),
			AccountEnabled: &enabled, UserType: get("usertype")}
		for name, i := range col {
			if !containsString(entraColumns, name) && i < len(rec) && strings.TrimSpace(rec[i]) != "" {
				u.rest = append(u.rest, header[i])
			}
		}
		exp.users = append(exp.users, u)
	}
	return exp, nil
}

// ImportEntra creates the export's people, in one transaction.
func ImportEntra(ctx context.Context, tx pgx.Tx, orgID string, exp *EntraExport, opts HostedOptions) (*Result, error) {
	people := make([]hostedPerson, 0, len(exp.users))
	guests := 0
	for _, u := range exp.users {
		p := hostedPerson{ID: u.ID, KeepID: true, Username: u.UserPrincipalName, Email: u.Mail,
			Given: strings.TrimSpace(u.GivenName), Surname: strings.TrimSpace(u.Surname),
			Display: strings.TrimSpace(u.DisplayName)}
		if u.AccountEnabled != nil && !*u.AccountEnabled {
			p.Off = "disabled"
		}
		if strings.EqualFold(u.UserType, "Guest") && p.Off == "" {
			guests++
		}
		for _, k := range u.rest {
			p.Lost = append(p.Lost, k)
		}
		people = append(people, p)
	}
	src := hostedSource{Name: "Entra ID", Dropped: []string{"every password (none is exported)"}}
	if guests > 0 {
		src.Dropped = append(src.Dropped, fmt.Sprintf("that %d of them are guests there (userType Guest); here they "+
			"are people of this organisation like any other", guests))
	}
	return importHosted(ctx, tx, orgID, src, people, opts)
}
