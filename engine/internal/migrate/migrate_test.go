package migrate

import (
	"strings"
	"testing"
	"testing/fstest"
)

func set(files ...string) fstest.MapFS {
	m := fstest.MapFS{}
	for _, f := range files {
		m[f] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	}
	return m
}

// The real migration set must always satisfy the rules. This is the test that
// fails the day someone adds 0005 without 0004.
func TestLoadRealSet(t *testing.T) {
	got, err := Load()
	if err != nil {
		t.Fatalf("the embedded migration set does not load: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i, m := range got {
		if m.Version != i+1 {
			t.Errorf("migration %d has version %d; versions must be contiguous from 1", i, m.Version)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("%04d_%s is empty", m.Version, m.Name)
		}
	}
}

func TestLoadFS(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		wantErr string
	}{
		{
			name:  "contiguous set loads",
			files: set("core/0001_bootstrap.sql", "core/0002_core.sql", "core/0003_views.sql"),
		},
		{
			// The important one. A gap means "walk N→N+1" cannot be honoured,
			// so it must fail at load rather than silently skipping.
			name:    "gap in the sequence is rejected",
			files:   set("core/0001_bootstrap.sql", "core/0003_views.sql"),
			wantErr: "contiguous",
		},
		{
			name:    "not starting at 1 is rejected",
			files:   set("core/0002_core.sql", "core/0003_views.sql"),
			wantErr: "contiguous",
		},
		{
			name:    "malformed filename is rejected",
			files:   set("core/0001_bootstrap.sql", "core/two.sql"),
			wantErr: "does not match",
		},
		{
			name:    "uppercase in the name is rejected",
			files:   set("core/0001_Bootstrap.sql"),
			wantErr: "does not match",
		},
		{
			name:    "empty set is rejected",
			files:   fstest.MapFS{},
			wantErr: "no migrations found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFS(tc.files)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected an error containing %q, got none", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("expected an error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// Sorting must be by parsed version, not by filename, so the tier split and the
// apply order stay correct if the numbering ever reaches four digits.
func TestLoadFSSortsByVersion(t *testing.T) {
	got, err := LoadFS(set(
		"core/0003_views.sql", "core/0001_bootstrap.sql", "core/0002_core.sql",
	))
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range got {
		if m.Version != i+1 {
			t.Fatalf("position %d holds version %d; not sorted ascending", i, m.Version)
		}
	}
}

// 0001 needs a superuser; everything after must run as signari_engine. Applying a
// core migration with superuser rights would silently create objects owned by the
// wrong role and quietly dissolve the GRANT boundary.
func TestTierSplit(t *testing.T) {
	for _, tc := range []struct {
		version int
		want    Tier
	}{
		{1, TierBootstrap},
		{2, TierCore},
		{3, TierCore},
		{99, TierCore},
	} {
		if got := (Migration{Version: tc.version}).Tier(); got != tc.want {
			t.Errorf("version %d: tier = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestNameParsing(t *testing.T) {
	got, err := LoadFS(set("core/0001_bootstrap.sql", "core/0002_rls_and_views.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "bootstrap" {
		t.Errorf("name = %q, want %q", got[0].Name, "bootstrap")
	}
	if got[1].Name != "rls_and_views" {
		t.Errorf("name = %q, want %q", got[1].Name, "rls_and_views")
	}
}
