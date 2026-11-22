package directory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"signari.dev/engine/internal/audit"
	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/store"
)

// An attribute map says which LDAP attribute feeds what here, remote name to local
// name (7.15). A local name is a declared attribute, whose declaration decides its
// type and whether it is sealed, or one of the two below, which say where a person's
// address or name is kept when a flavour's convention is wrong for this directory.
// A mapped attribute belongs to the directory: a sync puts back what it says.
const (
	MapEmail = "email"
	MapName  = "name"
)

// ldapAttributeName is RFC 4512's descriptor. An option such as ;binary is not
// accepted, nor * or +, which ask for everything.
var ldapAttributeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// checkAttributeMap refuses a map whose shape is wrong, before anything is written.
func checkAttributeMap(m map[string]string) error {
	feeding := make(map[string]string, len(m))
	for _, remote := range slices.Sorted(maps.Keys(m)) {
		local := m[remote]
		if !ldapAttributeName.MatchString(remote) {
			return sourceInvalid{fmt.Sprintf("%q is not an LDAP attribute name", remote)}
		}
		if local == "" {
			return sourceInvalid{fmt.Sprintf("%s feeds nothing: name a declared attribute, %s or %s", remote,
				MapEmail, MapName)}
		}
		if other, ok := feeding[local]; ok {
			return sourceInvalid{fmt.Sprintf("%s and %s both feed %q: a sync would keep whichever it read last",
				other, remote, local)}
		}
		feeding[local] = remote
	}
	return nil
}

// checkMapFits refuses a map the source cannot use: nothing but LDAP reads one, and
// a value with no declaration has no type, sensitivity or read rules, so nothing
// could be done with it. A map that clears needs neither.
func checkMapFits(ctx context.Context, q DB, orgID, slug string, m map[string]string) error {
	if len(m) == 0 {
		return nil
	}
	var kind string
	err := q.QueryRow(ctx, `SELECT kind FROM core.directory_sources WHERE org_id = $1::uuid AND slug = $2`,
		orgID, slug).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSourceUnknown
	}
	if err != nil {
		return err
	}
	if kind != "ldap" {
		return sourceInvalid{"an attribute map is for an ldap source; Google and Entra report what their APIs do"}
	}
	var missing string
	err = q.QueryRow(ctx, `
		SELECT n FROM unnest($2::text[]) AS n
		 WHERE NOT EXISTS (SELECT 1 FROM core.user_attribute_schema s WHERE s.org_id = $1::uuid AND s.name = n)
		 ORDER BY n LIMIT 1`, orgID, declaredFeeds(m)).Scan(&missing)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return sourceInvalid{fmt.Sprintf("the organisation declares no attribute %q: declare it first, since "+
		"that is what decides its type and whether it is sealed", missing)}
}

// declaredFeeds names the declared attributes a map feeds, in order.
func declaredFeeds(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, local := range m {
		if local != MapEmail && local != MapName {
			out = append(out, local)
		}
	}
	slices.Sort(out)
	return out
}

// attributePlan is what a sync would do to the attributes a source feeds.
type attributePlan struct {
	sets, clears []store.AttributeWrite
	// remoteOf names a person at the directory, for the record of one passed over.
	remoteOf map[string]string
	// refused are values that cannot be held, each named without its value, which
	// may be personal. unread are attributes no entry carried, so nobody's was
	// cleared: that is a bind account not allowed to read one, or a name mistyped,
	// far more often than a company with no departments. undeclared lost their
	// declaration after being mapped.
	refused, unread, undeclared []string
	// written is set once it is applied, with those passed over.
	privileged, erased int
}

// planAttributes compares what the directory says of the people this source is
// linked to with what is held. Somebody a plan would create has no link yet, so a
// preview leaves them out, and a sync reads them once they exist.
func planAttributes(ctx context.Context, pool *pgxpool.Pool, root *keys.RootKey, sourceID, orgID string,
	feeds map[string]string, remote []RemoteUser) (*attributePlan, error) {

	p := &attributePlan{remoteOf: map[string]string{}}
	names := declaredFeeds(feeds)
	if len(names) == 0 {
		return p, nil
	}
	declarations, err := store.Attributes(ctx, pool, orgID)
	if err != nil {
		return nil, err
	}
	declared := make(map[string]store.Attribute, len(declarations))
	for _, a := range declarations {
		declared[a.Name] = a
	}
	var live []string
	for _, n := range names {
		if _, ok := declared[n]; ok {
			live = append(live, n)
		} else {
			p.undeclared = append(p.undeclared, n)
		}
	}

	rows, err := pool.Query(ctx, `SELECT remote_id, user_id::text FROM core.directory_links WHERE source_id = $1::uuid`,
		sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	localOf := map[string]string{}
	var linked []string
	for rows.Next() {
		var remoteID, userID string
		if err := rows.Scan(&remoteID, &userID); err != nil {
			return nil, err
		}
		localOf[remoteID] = userID
		linked = append(linked, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	held, err := store.UserAttributeValues(ctx, pool, orgID, live, linked, root)
	if err != nil {
		return nil, err
	}

	carried := map[string]bool{}
	for _, u := range remote {
		for n := range u.Attributes {
			carried[n] = true
		}
	}
	for _, n := range live {
		if !carried[n] {
			p.unread = append(p.unread, n)
		}
	}
	for _, u := range remote {
		user, ok := localOf[u.ID]
		if !ok {
			continue
		}
		for _, n := range live {
			want, given := u.Attributes[n]
			have, holds := held[user][n]
			switch {
			case given && holds && want == have:
			case given:
				if err := attributeFits(declared[n], want); err != nil {
					p.refused = append(p.refused, fmt.Sprintf("%s of %s: %v", n, u.Email, err))
					continue
				}
				p.sets = append(p.sets, store.AttributeWrite{UserID: user, Name: n, Value: want})
				p.remoteOf[user] = u.ID
			case holds && carried[n] && declared[n].Required:
				p.refused = append(p.refused, fmt.Sprintf("%s of %s: required here and empty there", n, u.Email))
			case holds && carried[n]:
				p.clears = append(p.clears, store.AttributeWrite{UserID: user, Name: n})
				p.remoteOf[user] = u.ID
			}
		}
	}
	return p, nil
}

// attributeFits is whether a value can be held. An LDAP value is octets, so one can
// be a certificate or a SID, and PostgreSQL refuses text that is not UTF-8 or holds
// a NUL, failing every other person's value in the statement with it.
func attributeFits(a store.Attribute, value string) error {
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return errors.New("not text")
	}
	return store.CheckAttributeValue(a, value)
}

// applyAttributes writes a plan in one transaction. A privileged person's values
// are left alone, as the people pass leaves them, and the trail says so: these can
// feed claims, and whoever administers the directory is not thereby an
// administrator here. Clears go first, so a person the directory listed twice ends
// with what it said last.
func applyAttributes(ctx context.Context, pool *pgxpool.Pool, root *keys.RootKey, sourceID, orgID string,
	p *attributePlan) error {

	if len(p.sets)+len(p.clears) == 0 {
		return nil
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	people := make([]Action, 0, len(p.remoteOf))
	for user, remote := range p.remoteOf {
		people = append(people, Action{Kind: "attributes", UserID: user, RemoteID: remote})
	}
	kept, skipped, err := exceptPrivileged(ctx, tx, orgID, sourceID, people, func(a Action) string { return a.UserID })
	if err != nil {
		return err
	}
	p.privileged = skipped
	allowed := make(map[string]bool, len(kept))
	for _, a := range kept {
		allowed[a.UserID] = true
	}
	passedOver := func(w store.AttributeWrite) bool { return !allowed[w.UserID] }
	p.sets, p.clears = slices.DeleteFunc(p.sets, passedOver), slices.DeleteFunc(p.clears, passedOver)

	if err := store.ClearUserAttributes(ctx, tx, orgID, p.clears); err != nil {
		return err
	}
	if p.erased, err = store.SetUserAttributes(ctx, tx, orgID, p.sets, root); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, audit.Event{Type: "directory.attributes_synced", OrgID: orgID,
		Detail: map[string]any{"source_id": sourceID, "set": len(p.sets), "cleared": len(p.clears),
			"privileged_skipped": p.privileged, "erased": p.erased, "refused": len(p.refused)}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// maxDescribed is how many of a kind a report spells out.
const maxDescribed = 20

// describe says what a plan would do, or did, as the command prints it: nothing
// when there is nothing to say.
func (p *attributePlan) describe() string {
	var b strings.Builder
	if n := len(p.sets) + len(p.clears); n > 0 {
		fmt.Fprintf(&b, "%d set, %d cleared", len(p.sets), len(p.clears))
	}
	if p.privileged > 0 {
		fmt.Fprintf(&b, ", %d privileged people left alone", p.privileged)
	}
	if p.erased > 0 {
		fmt.Fprintf(&b, ", %d erased people left out", p.erased)
	}
	line := func(s string) { fmt.Fprintf(&b, "\n  %s", s) }
	for i, r := range p.refused {
		if i == maxDescribed {
			line(fmt.Sprintf("and %d more values refused", len(p.refused)-i))
			break
		}
		line("refused " + r)
	}
	for _, n := range p.unread {
		line(fmt.Sprintf("no entry carries what feeds %s, so nobody's was cleared: can the bind account read it?", n))
	}
	for _, n := range p.undeclared {
		line(fmt.Sprintf("%s is mapped and no longer declared, so nothing was read into it", n))
	}
	return strings.TrimPrefix(b.String(), "\n  ")
}
