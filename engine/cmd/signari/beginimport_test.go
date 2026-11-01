package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// An import's one transaction plans every statement, and only that transaction
// does (0.70). A plan settled on while the table is small stays until the commit,
// and an import of 32,000 people took 143 s with it and 32 s without. No table
// here looks the way a new deployment's does, so this reads the setting, which is
// the thing that was missing.
func TestAnImportPlansEveryStatementItRuns(t *testing.T) {
	dsn := os.Getenv("SIGNARI_TEST_DSN")
	if dsn == "" {
		t.Skip("SIGNARI_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	tx, err := beginImport(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := tx.QueryRow(ctx, `SELECT current_setting('plan_cache_mode')`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "force_custom_plan" {
		t.Errorf("an import's transaction has plan_cache_mode %s", mode)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT current_setting('plan_cache_mode')`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "auto" {
		t.Errorf("the setting outlived the transaction: plan_cache_mode is %s", mode)
	}
}

// All three importers go through it. One that opens its own transaction keeps the
// plans, and no test of a small import would notice.
func TestEveryImportBeginsThroughBeginImport(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{"importKeycloak": false, "importZitadel": false, "importAuthentik": false}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, listed := found[fn.Name.Name]; !listed {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "beginImport" {
					found[fn.Name.Name] = true
				}
			}
			return true
		})
	}
	for name, through := range found {
		if !through {
			t.Errorf("%s does not begin through beginImport", name)
		}
	}
}
