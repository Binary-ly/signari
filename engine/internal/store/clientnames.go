package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/language"
)

// A client's name in other languages (10.12, migration 0304): RFC 7591 section 2.2's
// client_name#<tag>. The untagged name is clients.display_name and is used as is wherever
// no tagged one suits the reader.

// MaxClientNames bounds how many languages one client may name itself in. A registrant is
// a stranger, and every name is a row and a line on a page.
const MaxClientNames = 32

// ErrInvalidClientName is a name or tag that cannot be stored.
var ErrInvalidClientName = errors.New("invalid localized client name")

// CleanClientName is a client's name as it may reach a page: control characters and the
// marks that reorder text (U+202A-U+202E, U+2066-U+2069) taken out, trimmed, and cut to
// sixty characters. It does not make the name trustworthy -- a stranger chose it -- which
// is why a consent screen shows the client_id beside it; it stops the name rearranging the
// page around it.
func CleanClientName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if r := []rune(name); len(r) > 60 {
		name = strings.TrimSpace(string(r[:60]))
	}
	return name
}

// NormaliseClientNames checks a set of names by tag before it is stored: each tag a
// well-formed BCP 47 tag the registry knows, kept as written; no two tags the same but
// for case (RFC 7591 section 2.2 compares them without regard to case); each name not
// empty once cleaned; and at most MaxClientNames. nil and empty both come back empty.
func NormaliseClientNames(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	if len(in) > MaxClientNames {
		return nil, fmt.Errorf("%w: %d languages, at most %d", ErrInvalidClientName, len(in), MaxClientNames)
	}
	seen := map[string]string{}
	tags := make([]string, 0, len(in))
	for tag := range in {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if _, err := language.Parse(tag); err != nil || !wellFormedTag(tag) {
			return nil, fmt.Errorf("%w: %q is not a BCP 47 language tag", ErrInvalidClientName, tag)
		}
		if other, dup := seen[strings.ToLower(tag)]; dup {
			return nil, fmt.Errorf("%w: %q and %q are the same tag, which is compared without regard to case",
				ErrInvalidClientName, other, tag)
		}
		seen[strings.ToLower(tag)] = tag
		name := CleanClientName(in[tag])
		if name == "" {
			return nil, fmt.Errorf("%w: the name for %q is empty", ErrInvalidClientName, tag)
		}
		out[tag] = name
	}
	return out, nil
}

// wellFormedTag is the column's CHECK, so a tag refused there is refused here first, with
// the reason, rather than as a constraint violation.
func wellFormedTag(tag string) bool {
	for i, sub := range strings.Split(tag, "-") {
		if len(sub) < 1 || len(sub) > 8 {
			return false
		}
		for _, r := range sub {
			letter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			if !letter && !(i > 0 && r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// ClientNames is one client's names by tag, empty for none.
func ClientNames(ctx context.Context, q Querier, clientID string) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT tag, name FROM core.client_localized_names WHERE client_id = $1`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tag, name string
		if err := rows.Scan(&tag, &name); err != nil {
			return nil, err
		}
		out[tag] = name
	}
	return out, rows.Err()
}

// ClientNamesOf is several clients' names, by client and then by tag, in one statement:
// a page listing applications asks once, not once for each.
func ClientNamesOf(ctx context.Context, q Querier, clientIDs []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	if len(clientIDs) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT client_id, tag, name FROM core.client_localized_names
		WHERE client_id = ANY($1::text[])`, clientIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, tag, name string
		if err := rows.Scan(&id, &tag, &name); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]string{}
		}
		out[id][tag] = name
	}
	return out, rows.Err()
}

// SetClientNames makes names the client's names in other languages, replacing what it
// had; empty takes them all away. db is the caller's transaction, so the names change
// with whatever else the write changes.
func SetClientNames(ctx context.Context, db Execer, orgID, clientID string, names map[string]string) error {
	clean, err := NormaliseClientNames(names)
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `DELETE FROM core.client_localized_names WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("replacing a client's names: %w", err)
	}
	tags := make([]string, 0, len(clean))
	values := make([]string, 0, len(clean))
	for tag, name := range clean {
		tags, values = append(tags, tag), append(values, name)
	}
	if len(tags) == 0 {
		return nil
	}
	if _, err := db.Exec(ctx, `INSERT INTO core.client_localized_names (client_id, org_id, tag, name)
		SELECT $1, $2::uuid, t, n FROM unnest($3::text[], $4::text[]) AS x(t, n)`,
		clientID, orgID, tags, values); err != nil {
		return fmt.Errorf("storing a client's names: %w", err)
	}
	return nil
}
