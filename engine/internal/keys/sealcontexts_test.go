package keys

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Everything the code seals under the root key is something a rotation re-seals.
//
// The classification test reads column types, so it can see a bytea column and
// cannot see a sealed value inside a JSON payload. The CIBA push tokens lived
// there for a release, under the root key, and a rotation would have left every
// delivery in flight unopenable. So this test works from the other end: it finds
// each call that seals with the root key, resolves the context it seals under,
// and requires the rotation to know that context, as a column or as a JSON field.
func TestEveryRootSealContextIsRotated(t *testing.T) {
	root := filepath.Join("..", "..")
	sources := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") ||
			strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sources[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) < 50 {
		t.Fatalf("only %d source files read; the walk is wrong", len(sources))
	}

	// Every string constant, by name, so a context passed as a constant can be
	// resolved to the value it seals under.
	constants := map[string][]string{}
	constRe := regexp.MustCompile(`(?m)^\s*(?:const\s+)?([A-Za-z_]\w*)\s*(?:[A-Za-z_][\w.]*\s*)?=\s*"([^"]*)"`)
	for _, src := range sources {
		for _, m := range constRe.FindAllStringSubmatch(src, -1) {
			constants[m[1]] = append(constants[m[1]], m[2])
		}
	}

	// A receiver named root, or ending in .root or .Root: the root key. A
	// subject key is sk, and AES-GCM in the SAML code is gcm. The unexported
	// seal is the context-less form signing keys and subject keys use.
	callRe := regexp.MustCompile(`\b[rR]oot\.([sS]eal)\(`)
	sealed := map[string][]string{} // context -> where
	for path, src := range sources {
		for _, loc := range callRe.FindAllStringSubmatchIndex(src, -1) {
			line := strings.Count(src[:loc[0]], "\n") + 1
			where := fmt.Sprintf("%s:%d", path, line)
			args := callArgs(src[loc[1]:])
			if src[loc[2]:loc[3]] == "seal" && len(args) == 1 {
				sealed[""] = append(sealed[""], where)
				continue
			}
			if len(args) != 2 {
				t.Errorf("%s: a root Seal call this test cannot read (%d arguments)", where, len(args))
				continue
			}
			arg := strings.TrimSpace(args[1])
			var values []string
			if strings.HasPrefix(arg, `"`) {
				values = []string{strings.Trim(arg, `"`)}
			} else {
				name := arg[strings.LastIndex(arg, ".")+1:]
				values = constants[name]
			}
			if len(values) == 0 {
				t.Errorf("%s: seals under %s, which this test cannot resolve to a string; "+
					"use a string constant or literal so the rotation can be checked", where, arg)
				continue
			}
			for _, v := range values {
				sealed[v] = append(sealed[v], where)
			}
		}
	}
	if len(sealed) < 5 {
		t.Fatalf("only %d root seal contexts found; the scan is wrong", len(sealed))
	}

	rotated := map[string]bool{}
	for _, c := range rootSealedColumns {
		rotated[c.context] = true
	}
	for _, f := range rootSealedFields {
		rotated[f.context] = true
	}
	for c := range rootSealedOutsideTheDatabase {
		if len(sealed[c]) == 0 {
			t.Errorf("rootSealedOutsideTheDatabase names %q, which nothing seals under any more; remove it", c)
		}
		rotated[c] = true
	}
	var missing []string
	for ctxName, where := range sealed {
		if !rotated[ctxName] {
			sort.Strings(where)
			missing = append(missing, fmt.Sprintf("%q (sealed at %s)", ctxName, strings.Join(where, ", ")))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("the root key seals under %s, and a rotation re-seals nothing under "+
			"that context: after one, those values open with no key. Add the column "+
			"to rootSealedColumns or the JSON field to rootSealedFields", m)
	}
}

// rootSealedOutsideTheDatabase are the contexts the root key seals values under
// that are never stored, so a rotation has nothing to re-seal. Each says where
// the value lives and why one sealed before a rotation costs nobody more than
// starting again.
var rootSealedOutsideTheDatabase = map[string]string{
	"signari email sign-in page": "the emailed sign-in's code page cookie (httpapi/emailsignin.go), " +
		"fifteen minutes long: an online rotation's accepted key opens one sealed before it, " +
		"and after an offline one the person asks for the code again",
}

// callArgs splits the arguments of a call whose opening parenthesis has just
// been consumed, at top-level commas, up to the matching close.
func callArgs(s string) []string {
	var args []string
	depth, start := 0, 0
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr != 0:
			if c == '\\' && inStr == '"' {
				i++
			} else if c == inStr {
				inStr = 0
			}
		case c == '"' || c == '`' || c == '\'':
			inStr = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return append(args, s[start:i])
			}
			depth--
		case c == ',' && depth == 0:
			args = append(args, s[start:i])
			start = i + 1
		}
	}
	return nil
}

// A sealed value inside a JSON payload is re-sealed in place, under the new
// key, and the old key no longer opens it.
//
// Narrowed to one row of this test's own: the shared test database holds rows
// sealed under other tests' keys, which a full rotation would rightly refuse.
func TestARotationReSealsAValueInsideJSON(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	old, err := NewRootKey("v1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewRootKey("v2", []byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatal(err)
	}

	var field sealedField
	for _, f := range rootSealedFields {
		if f.field == "credentials" {
			field = f
		}
	}
	if field.table == "" {
		t.Fatal("no rotation entry for the CIBA delivery credentials")
	}
	subject := fmt.Sprintf("rewrap-%d", time.Now().UnixNano())
	field.where += fmt.Sprintf(" AND subject_key = '%s'", subject)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	blob, err := old.Seal([]byte(`{"token":"t","auth_req_id":"a"}`), field.context)
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"endpoint":"https://rp.test/cb","client_id":"c","credentials":%q}`,
		base64.StdEncoding.EncodeToString(blob))
	if _, err := tx.Exec(ctx, `
		INSERT INTO core.outbox (topic, payload, next_attempt_at, subject_key)
		VALUES ('ciba_ping', $1, 'infinity', $2)`, payload, subject); err != nil {
		t.Fatal(err)
	}

	rep, err := rewrapField(ctx, tx, field, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rows != 1 {
		t.Fatalf("re-sealed %d rows, want 1", rep.Rows)
	}

	var encoded, endpoint string
	if err := tx.QueryRow(ctx, `
		SELECT payload->>'credentials', payload->>'endpoint' FROM core.outbox
		 WHERE subject_key = $1`, subject).Scan(&encoded, &endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://rp.test/cb" {
		t.Errorf("the rest of the payload was disturbed: endpoint = %q", endpoint)
	}
	resealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := next.Open(resealed, field.context); err != nil ||
		string(plain) != `{"token":"t","auth_req_id":"a"}` {
		t.Errorf("the new key does not open the re-sealed value: %v", err)
	}
	if _, err := old.Open(resealed, field.context); err == nil {
		t.Error("the old key still opens the re-sealed value; retiring it retires nothing")
	}
}
