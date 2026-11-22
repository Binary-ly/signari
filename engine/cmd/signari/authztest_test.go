package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// `authz test` is for CI, where nothing is listening, so what it says about a
// model file comes from the file: the parse that storing it would run.
func TestAuthzTestReadsAModelWithNoDatabase(t *testing.T) {
	t.Setenv("SIGNARI_DSN", "")
	write := func(body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "model.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const model = `
types:
  document:
    relations:
      viewer: []
    permissions:
      read: [viewer]
tests:
  - name: a viewer may read
    subject: user:x
    action: read
    resource: document:1
    relations: [viewer]
    allow: true
`
	if err := authzTest(write(model)); err != nil {
		t.Errorf("a sound model was refused: %v", err)
	}
	err := authzTest(write(strings.Replace(model, "allow: true", "allow: false", 1)))
	if err == nil || !strings.Contains(err.Error(), "a viewer may read") {
		t.Errorf("a model whose own test fails answered %v, want it named", err)
	}
	if err := authzTest(""); err == nil {
		t.Error("no file was accepted")
	}
}

// A grant that has already ended would read as done and grant nothing.
func TestAGrantCannotEndBeforeItBegins(t *testing.T) {
	if _, err := grantExpiry(-time.Hour); err == nil {
		t.Error("a negative -expires-in was accepted")
	}
	if at, err := grantExpiry(0); err != nil || at != nil {
		t.Errorf("no -expires-in gave %v, %v", at, err)
	}
	at, err := grantExpiry(time.Hour)
	if err != nil || at == nil || time.Until(*at) < 59*time.Minute {
		t.Errorf("-expires-in 1h gave %v, %v", at, err)
	}
}
