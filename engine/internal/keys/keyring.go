package keys

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Online root-key rotation (3.13).
//
// # What went wrong without it
//
// A rotation re-sealed every row in one transaction and then needed every
// node switched at once. A node still on the old key after the commit could
// open nothing; a node given the new key before it sealed rows the others
// could not open; and a node on the old key sealing a row after the rewrap had
// read the table left that row under a key about to be destroyed. So it was a
// stop-the-world change, and a missed node lost data silently.
//
// # How it goes now
//
// A node may hold a second root key it opens with and never seals with,
// SIGNARI_ACCEPTED_ROOT_KEY. Then:
//
//  1. every node: SIGNARI_ROOT_KEY=old, SIGNARI_ACCEPTED_ROOT_KEY=new. Nothing
//     seals with the new key yet, and every node can open it.
//  2. every node: SIGNARI_ROOT_KEY=new, SIGNARI_ACCEPTED_ROOT_KEY=old. Rows
//     are sealed with the new key, and every node, either side of the restart,
//     opens both.
//  3. `signari keys rewrap-root` moves what is left under the old key to the
//     new one. It refuses while any running node still seals with the old key,
//     which each says in its connections' application_name (PoolTag).
//  4. every node: SIGNARI_ACCEPTED_ROOT_KEY removed.

// WithAccepted returns this key also holding other, to open with and never to
// seal with.
func (r *RootKey) WithAccepted(other *RootKey) (*RootKey, error) {
	if other.ref == r.ref {
		return nil, fmt.Errorf("the accepted root key has the same ref %q as the root key; "+
			"the two must be told apart in stored rows", r.ref)
	}
	if other.tag == r.tag {
		return nil, fmt.Errorf("the accepted root key is the root key itself")
	}
	c := *r
	c.accepted = []*RootKey{other.alone()}
	return &c, nil
}

// alone is this key without any it accepts: what a rotation seals with and
// what it tests a blob against, where opening with either would not say which
// key a row is under.
func (r *RootKey) alone() *RootKey {
	c := *r
	c.accepted = nil
	return &c
}

// Accepted is the key this one also opens with, or nil.
func (r *RootKey) Accepted() *RootKey {
	if len(r.accepted) == 0 {
		return nil
	}
	return r.accepted[0]
}

// forRef is the key in this ring a row recorded as its wrapper, or nil.
func (r *RootKey) forRef(ref string) *RootKey {
	if ref == r.ref {
		return r.alone()
	}
	for _, a := range r.accepted {
		if a.ref == ref {
			return a
		}
	}
	return nil
}

func (r *RootKey) refsHeld() string {
	if a := r.Accepted(); a != nil {
		return fmt.Sprintf("%q and %q are", r.ref, a.ref)
	}
	return fmt.Sprintf("%q is", r.ref)
}

// PoolTag is what a node's connections add to their application_name: which
// key it seals with and which it also opens with, by a one-way tag of each
// key's material. A running node is visible in pg_stat_activity for exactly as
// long as it holds connections, so this is how a rotation learns what every
// node is doing without a registry that could go stale.
func (r *RootKey) PoolTag() string {
	t := "seals=" + r.tag
	for _, a := range r.accepted {
		t += " opens=" + a.tag
	}
	return t
}

// LoadRootKeyring reads the root key and, when one is configured, the root key
// it also accepts (SIGNARI_ACCEPTED_ROOT_KEY, _FILE and _REF), by the same
// rules as the root key itself.
func LoadRootKeyring(getenv func(string) string) (*RootKey, error) {
	root, err := LoadRootKey(getenv, "SIGNARI_ROOT_KEY", "SIGNARI_ROOT_KEY_FILE", "SIGNARI_ROOT_KEY_REF")
	if err != nil {
		return nil, err
	}
	if getenv("SIGNARI_ACCEPTED_ROOT_KEY") == "" && getenv("SIGNARI_ACCEPTED_ROOT_KEY_FILE") == "" {
		return root, nil
	}
	accepted, err := LoadRootKey(getenv,
		"SIGNARI_ACCEPTED_ROOT_KEY", "SIGNARI_ACCEPTED_ROOT_KEY_FILE", "SIGNARI_ACCEPTED_ROOT_KEY_REF")
	if err != nil {
		return nil, fmt.Errorf("the accepted root key: %w", err)
	}
	return root.WithAccepted(accepted)
}

// NodesNotSealingWith lists the running nodes whose connections say they seal
// with a key other than want, and those that say nothing because they run a
// release from before the tag under the default names. A node of an earlier
// release given a name of its own cannot be seen; the rotation guide says to
// upgrade every node first.
func NodesNotSealingWith(ctx context.Context, conn *pgx.Conn, want *RootKey) ([]string, error) {
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT coalesce(host(client_addr), 'local socket') || ': ' || application_name
		  FROM pg_stat_activity
		 WHERE datname = current_database() AND pid <> pg_backend_pid()
		   AND (application_name IN ('signari', 'signari workers')
		        OR (application_name ~ ' seals=[0-9a-f]{8}( |$)'
		            AND application_name !~ (' seals=' || $1 || '( |$)')))
		 ORDER BY 1`, want.tag)
	if err != nil {
		return nil, fmt.Errorf("reading which nodes are connected: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WithPoolTag appends tag to an application_name, cutting the name rather than
// the tag to fit PostgreSQL's 63 bytes: a node whose tag was cut would be
// invisible to the rotation.
func WithPoolTag(name, tag string) string {
	if tag == "" {
		return name
	}
	const max = 63
	if room := max - len(tag) - 1; len(name) > room {
		name = strings.TrimSpace(name[:room])
	}
	return name + " " + tag
}
