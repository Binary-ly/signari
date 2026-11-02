package pages

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/i18n"
)

func putTheme(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// layoutWith is the built-in layout with a mark in it, which is valid by
// construction, so what a test sees is which one was served.
func layoutWith(t *testing.T, mark string) string {
	t.Helper()
	return strings.Replace(BuiltIn()["layout"], "</body>", "<i hidden>"+mark+"</i></body>", 1)
}

func renderLogin(t *testing.T, s *Set, lang string) string {
	t.Helper()
	var b bytes.Buffer
	if err := s.ExecuteIn(&b, lang, "login", map[string]any{"CSRF": "c", "Authz": "a"}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// An organisation's directory is laid over the deployment's, page by page and
// message by message, and what it does not name is the deployment's: everybody
// else's set, and the deployment's own, do not change.
func TestAnOrganisationsThemeIsLaidOverTheDeployments(t *testing.T) {
	dir := t.TempDir()
	putTheme(t, filepath.Join(dir, "layout.html"), layoutWith(t, "deployment layout"))
	putTheme(t, filepath.Join(dir, "locales", "en.json"), `{"login.submit": "Deployment go"}`)
	putTheme(t, filepath.Join(dir, "orgs", "acme", "layout.html"), layoutWith(t, "acme layout"))
	putTheme(t, filepath.Join(dir, "orgs", "acme", "locales", "en.json"), `{"login.heading": "Acme, sign in"}`)
	putTheme(t, filepath.Join(dir, "orgs", "bravo", "locales", "en.json"), `{"login.submit": "Bravo go"}`)

	set := loadOrFail(t, dir)
	if got := strings.Join(set.OrgThemes(), " "); got != "acme bravo" {
		t.Fatalf("the themes are %q", got)
	}

	acme := renderLogin(t, set.For("acme"), "en")
	if !strings.Contains(acme, "acme layout") || strings.Contains(acme, "deployment layout") {
		t.Errorf("acme's layout was not served")
	}
	if !strings.Contains(acme, "Acme, sign in") {
		t.Error("acme's own message was not served")
	}
	if !strings.Contains(acme, "Deployment go") {
		t.Error("what acme does not reword should be the deployment's")
	}

	bravo := renderLogin(t, set.For("bravo"), "en")
	if !strings.Contains(bravo, "deployment layout") || strings.Contains(bravo, "acme layout") {
		t.Error("a theme with no layout should wear the deployment's")
	}
	if !strings.Contains(bravo, "Bravo go") || strings.Contains(bravo, "Deployment go") {
		t.Error("a message both reword should be the organisation's")
	}

	plain := renderLogin(t, set.For("nobody"), "en")
	if set.For("nobody") != set || strings.Contains(plain, "Acme") {
		t.Error("an organisation with no theme should have the deployment's pages")
	}
	if origin := set.For("acme").Origin("layout"); !strings.Contains(origin, filepath.Join("orgs", "acme")) {
		t.Errorf("acme's layout is said to come from %q", origin)
	}
}

// The rule for a deployment's theme holds for a tenant's directory, and one bad
// directory costs nobody else anything: a typo must never stop anybody signing in.
func TestARefusedThemeFileCostsOnlyThatFile(t *testing.T) {
	dir := t.TempDir()
	putTheme(t, filepath.Join(dir, "layout.html"), layoutWith(t, "deployment layout"))
	putTheme(t, filepath.Join(dir, "orgs", "acme", "logn.html"), `{{define "content"}}typo{{end}}`)
	// Answers no CSRF field, so it would be a form that can never be submitted.
	putTheme(t, filepath.Join(dir, "orgs", "acme", "login.html"), `{{define "content"}}<form></form>{{end}}`)
	putTheme(t, filepath.Join(dir, "orgs", "acme", "locales", "en.json"), `{"login.haeding": "typo"}`)
	putTheme(t, filepath.Join(dir, "orgs", "bravo", "locales", "en.json"), `{not json`)
	putTheme(t, filepath.Join(dir, "orgs", "a-file-not-a-directory"), "ignored")

	set, problems, err := Load(dir)
	if err != nil {
		t.Fatalf("a bad organisation's theme stopped the pages loading: %v", err)
	}
	said := ""
	for _, p := range problems {
		said += p.Error() + "\n"
	}
	for _, want := range []string{"logn.html", filepath.Join("acme", "login.html"), "login.haeding", "bravo"} {
		if !strings.Contains(said, want) {
			t.Errorf("the refusals do not name %q:\n%s", want, said)
		}
	}
	got := renderLogin(t, set.For("acme"), "en")
	if !strings.Contains(got, "deployment layout") || !strings.Contains(got, `name="password"`) {
		t.Errorf("a refused page should leave the deployment's: %.200s", got)
	}

	// `theme check` says the same, naming where each file is.
	ok, checked := Check(dir)
	said = ""
	for _, p := range checked {
		said += p.Error() + "\n"
	}
	prefix := filepath.Join("orgs", "acme") + string(filepath.Separator)
	for _, want := range []string{prefix + "logn.html", prefix + "login.html"} {
		if !strings.Contains(said, want) {
			t.Errorf("theme check does not name %q:\n%s", want, said)
		}
	}
	if strings.Join(ok, " ") != "layout" {
		t.Errorf("theme check passed %v", ok)
	}
}

// A theme directory of nothing but organisations' themes is one to check.
func TestAThemeOfOnlyOrganisationsIsChecked(t *testing.T) {
	dir := t.TempDir()
	putTheme(t, filepath.Join(dir, "orgs", "acme", "layout.html"), layoutWith(t, "acme layout"))
	ok, problems := Check(dir)
	if len(problems) != 0 || len(ok) != 1 || ok[0] != filepath.Join("orgs", "acme", "layout") {
		t.Errorf("checked %v, refused %v", ok, problems)
	}
}

// Rendering through a printer that carries words reaches the whole page, the
// shared layout included, and leaves the shared trees alone for the next request.
func TestAPageSaysAnOrganisationsWords(t *testing.T) {
	set := loadOrFail(t, "")
	data := map[string]any{"CSRF": "c", "Authz": "a"}
	var b bytes.Buffer
	own := set.Bundle().For(i18n.Default).With(map[string]string{"login.heading": "Acme <b>"})
	if err := set.ExecuteWith(&b, own, "login", data); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); !strings.Contains(got, "Acme &lt;b&gt;") {
		t.Errorf("the page does not say the organisation's words: %.200s", got)
	}
	if strings.Contains(renderLogin(t, set, i18n.Default), "Acme") {
		t.Error("one organisation's words reached the next render")
	}
	if err := set.ExecuteWith(&b, own, "nosuchpage", data); err == nil {
		t.Error("a page that does not exist rendered")
	}
	if err := set.ExecuteWith(&b, own, "layout", data); err == nil {
		t.Error("a partial rendered as a page")
	}

	// Parsing per render is the cost of this path; the catalogue's own take the
	// parsed trees, so a printer with no words renders what ExecuteIn does.
	var a, c bytes.Buffer
	plain := set.Bundle().For(i18n.Default)
	if err := set.ExecuteWith(&a, plain, "login", data); err != nil {
		t.Fatal(err)
	}
	if err := set.ExecuteIn(&c, i18n.Default, "login", data); err != nil {
		t.Fatal(err)
	}
	if a.String() != c.String() {
		t.Error("a printer with no words rendered differently")
	}
}
