package migrate

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var notesOut = flag.String("schema-notes-out", "", "write the schema version notes here, to copy over "+
	"docs/schema-versions.md")

// fileLine is a header's first line naming the file, which says nothing new.
var fileLine = regexp.MustCompile(`^\d{4}_[a-z0-9_]+\.sql$`)

// summary is a migration's own description: the first paragraph of its
// leading comment that is not its file name or a heading, joined into one.
func summary(sql string) string {
	var para []string
	for _, line := range strings.Split(sql, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "--") {
			if t == "" && len(para) == 0 {
				continue
			}
			break
		}
		text := strings.TrimSpace(strings.TrimPrefix(t, "--"))
		switch {
		case text == "" || strings.HasPrefix(text, "#") || "-- "+text == compatibleMarker || fileLine.MatchString(text):
			if len(para) > 0 {
				return strings.Join(para, " ")
			}
		default:
			para = append(para, text)
		}
	}
	return strings.Join(para, " ")
}

// escapeAngles writes < and > outside code spans as entities, so that
// `<issuer>/admin` in a header is not read as an HTML tag and dropped.
func escapeAngles(s string) string {
	var b strings.Builder
	code := false
	for _, r := range s {
		switch {
		case r == '`':
			code = !code
			b.WriteRune(r)
		case !code && r == '<':
			b.WriteString("&lt;")
		case !code && r == '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// notes renders what each schema version did (6.22).
func notes(all []Migration) []byte {
	var b strings.Builder
	b.WriteString("# Schema versions\n\n" +
		"Each release's binary expects one schema version and refuses to start against another, unless\n" +
		"the migrations between them were each declared compatible with the release before. This page\n" +
		"is what each version did, in its own words: the first paragraph of each migration's header.\n" +
		"It is generated from the migrations the binary embeds, by `engine/internal/migrate`'s\n" +
		"`TestTheSchemaVersionNotesAreCurrent`; do not edit it by hand. How to upgrade, and what\n" +
		"\"compatible\" lets you do during one, is in [upgrading.md](upgrading.md).\n\n")
	for i := len(all) - 1; i >= 0; i-- {
		m := all[i]
		fmt.Fprintf(&b, "## %04d %s\n\n", m.Version, m.Name)
		switch {
		case m.Tier() == TierBootstrap:
			b.WriteString("The bootstrap: roles, schemas and grants, run once with a superuser.\n\n")
		case m.CompatibleWithPrevious():
			b.WriteString("Compatible with the release before: its binary may still serve this schema.\n\n")
		default:
			b.WriteString("Not compatible with the release before: stop it before migrating.\n\n")
		}
		if s := summary(m.SQL); s != "" {
			b.WriteString(escapeAngles(s) + "\n\n")
		}
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n")
}

// The published notes are the ones the embedded migrations make (6.22).
// Regenerate them with `go test ./internal/migrate -run
// TheSchemaVersionNotesAreCurrent -schema-notes-out <file>`.
func TestTheSchemaVersionNotesAreCurrent(t *testing.T) {
	all, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := notes(all)
	if *notesOut != "" {
		if err := os.WriteFile(*notesOut, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "schema-versions.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, published) {
		t.Error("docs/schema-versions.md is not what the embedded migrations make; regenerate it with " +
			"-schema-notes-out")
	}
}

func TestASummaryIsTheHeadersFirstParagraph(t *testing.T) {
	for sql, want := range map[string]string{
		"-- 0195_x.sql\n--\n-- A handle of 1 to 64\n-- bytes.\n--\n-- More.\nALTER": "A handle of 1 to 64 bytes.",
		"-- # Heading\n--\n-- The point.\nSELECT 1;":                                "The point.",
		"\nCREATE TABLE x ();": "",
		"-- signari:compatible-with-previous\n--\n-- Adds a column.\nALTER": "Adds a column.",
	} {
		if got := summary(sql); got != want {
			t.Errorf("summary(%q) = %q, want %q", sql, got, want)
		}
	}
}
