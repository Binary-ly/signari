package docsync

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Guard 0.08i, the metrics half: every counter and histogram the engine
// declares, and therefore exports on /metrics, is incremented by something
// that is not a test. signari_signins_total, signari_tokens_issued_total and
// signari_auth_failures_total were declared, documented and scraped, and
// nothing incremented them: a dashboard of sign-in failures read zero through
// an attack, which is worse than having no such series.
func TestEveryDeclaredMetricIsIncremented(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "engine/internal/metrics/engine.go"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "engine.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Engine" {
			return true
		}
		for _, fl := range ts.Type.(*ast.StructType).Fields.List {
			star, ok := fl.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if id, ok := star.X.(*ast.Ident); ok && (id.Name == "Counter" || id.Name == "Histogram") {
				for _, name := range fl.Names {
					fields = append(fields, name.Name)
				}
			}
		}
		return false
	})
	if len(fields) < 4 {
		t.Fatalf("read %d metric fields off metrics.Engine; the walk is not reading it", len(fields))
	}

	var code strings.Builder
	err = filepath.Walk(filepath.Join(root, "engine"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		code.Write(b)
		code.WriteString("\n")
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	all := code.String()
	for _, field := range fields {
		if !regexp.MustCompile(`\.` + field + `\.(Inc|Add|Observe)\(`).MatchString(all) {
			t.Errorf("metrics.Engine.%s is declared and exported on /metrics, and nothing that is "+
				"not a test increments it, so it reads zero for as long as it is served; "+
				"increment it where the thing it counts happens, or remove it", field)
		}
	}
}
