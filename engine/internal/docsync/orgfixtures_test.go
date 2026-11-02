package docsync

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shared test database once held 278,628 organisations and 304,839 users,
// 33,222 of them from one fixture that made an organisation per call and removed
// nothing, and every sign-in page counts them. So a test that makes an organisation
// says how it goes: storetest.Forget, which fails the test when it cannot, or a
// transaction it rolls back. A delete of its own only counts while it is known to
// work, because a person or a client holds an organisation and an ignored error
// hides that: the SCIM fixture left 53 in one run behind `_, _ = pool.Exec`.
func TestEveryOrganisationATestMakesIsRemoved(t *testing.T) {
	root := repoRoot(t)
	engine := filepath.Join(root, "engine")
	fn := regexp.MustCompile(`(?m)^func `)
	insert := "INSERT INTO core.organizations"
	anyOrganisation := regexp.MustCompile(`FROM core\.organizations( WHERE [^\n]*?)? LIMIT 1`)
	checked := 0

	err := filepath.Walk(engine, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(raw)
		rel, _ := filepath.Rel(root, path)
		if m := anyOrganisation.FindString(src); m != "" && !strings.Contains(m, "ORDER BY") &&
			!strings.HasSuffix(path, "orgfixtures_test.go") {
			t.Errorf("%s takes whichever organisation comes first, and in a shared database that is one another "+
				"test is about to remove: order it by created_at for the oldest, or make one. Near: %s", rel, m)
		}
		if !strings.Contains(src, insert) {
			return nil
		}
		starts := append(fn.FindAllStringIndex(src, -1), []int{len(src), len(src)})
		for i := 0; i+1 < len(starts); i++ {
			body := src[starts[i][0]:starts[i+1][0]]
			if !strings.Contains(body, insert) {
				continue
			}
			checked++
			name := strings.SplitN(strings.TrimPrefix(body, "func "), "(", 2)[0]
			if strings.Contains(body, "storetest.Forget") || strings.Contains(body, "Rollback(") ||
				strings.Contains(body, " pgx.Tx") || strings.Contains(body, "DELETE FROM core.organizations") {
				continue
			}
			if reason, ok := leftOnPurpose[strings.TrimPrefix(rel, "engine/")+" "+name]; ok && reason != "" {
				continue
			}
			t.Errorf("%s: %s makes an organisation and does not say how it goes; storetest.Forget it, "+
				"or make it in a transaction that is rolled back", rel, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 80 {
		t.Fatalf("only %d fixtures were found, so the walk is wrong", checked)
	}
}

// leftOnPurpose is a fixture that stays, and why.
var leftOnPurpose = map[string]string{
	"cmd/signari/fips_test.go TestServeRefusesWhatFIPSOnlyCannotRun": "a database of its own, dropped with the test",
	"internal/adminapi/precondition_test.go anyOrgID": "the one organisation an empty database needs, kept " +
		"for the fixtures that hang off it and found again by the next",
	"internal/directory/applycost_test.go BenchmarkASyncOfAHundredThousand": "a benchmark, on the throwaway " +
		"database SIGNARI_DESTRUCTIVE_TEST_DSN names",
}
