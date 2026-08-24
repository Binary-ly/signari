package fidomds

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// withTable builds a resolver whose catalogue is set directly, bypassing the
// network. The AAGUID resolution logic is what these tests exercise; the BLOB
// decoding is the go-webauthn library's own concern.
func withTable(t map[uuid.UUID]string) *Resolver {
	r := &Resolver{log: quietLog()}
	r.table.Store(&t)
	r.loaded.Store(true)
	return r
}

// A real YubiKey 5 series AAGUID, so the test resolves the same 16 bytes a
// credential actually stores.
const yubi5 = "ee882879-721c-4913-9775-3dfcce97072a"

func TestModelResolvesAStoredAAGUID(t *testing.T) {
	id := uuid.MustParse(yubi5)
	r := withTable(map[uuid.UUID]string{id: "YubiKey 5 NFC"})

	got, ok := r.Model(id[:])
	if !ok {
		t.Fatalf("a known AAGUID did not resolve")
	}
	if got != "YubiKey 5 NFC" {
		t.Errorf("resolved %q, want %q", got, "YubiKey 5 NFC")
	}
}

func TestModelUnknownAAGUIDDoesNotResolve(t *testing.T) {
	known := uuid.MustParse(yubi5)
	other := uuid.MustParse("00000000-0000-0000-0000-0000000000ff")
	r := withTable(map[uuid.UUID]string{known: "YubiKey 5 NFC"})

	if _, ok := r.Model(other[:]); ok {
		t.Error("an AAGUID absent from the catalogue resolved to a model")
	}
}

// The all-zero AAGUID is what many platform authenticators send to avoid being
// fingerprinted. It is the absence of a model, and must never map to one even if
// a catalogue somehow carried an entry for it.
func TestModelRejectsTheNilAAGUID(t *testing.T) {
	r := withTable(map[uuid.UUID]string{uuid.Nil: "should never be shown"})
	zero := make([]byte, 16)
	if got, ok := r.Model(zero); ok {
		t.Errorf("the all-zero AAGUID resolved to %q; it must be treated as no model", got)
	}
}

func TestModelRejectsWrongLength(t *testing.T) {
	r := withTable(map[uuid.UUID]string{uuid.MustParse(yubi5): "YubiKey 5 NFC"})
	for _, b := range [][]byte{nil, {}, make([]byte, 15), make([]byte, 17)} {
		if _, ok := r.Model(b); ok {
			t.Errorf("a %d-byte AAGUID resolved; only 16 bytes is a valid AAGUID", len(b))
		}
	}
}

// A nil resolver is the unconfigured case, and every caller relies on it being
// safe so no notice path has to nil-check before naming a passkey.
func TestNilResolverIsSafe(t *testing.T) {
	var r *Resolver
	if _, ok := r.Model(make([]byte, 16)); ok {
		t.Error("a nil resolver resolved a model")
	}
	if r.Loaded() {
		t.Error("a nil resolver reported itself loaded")
	}
	if r.Size() != 0 {
		t.Error("a nil resolver reported a non-zero size")
	}
}

func TestNewFromEnvSelectsASource(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantNil bool
		wantURL string
		want    string // "path", "url", or ""
	}{
		{name: "nothing configured", env: nil, wantNil: true},
		{name: "path", env: map[string]string{"SIGNARI_FIDO_MDS_PATH": "/etc/mds.jwt"}, want: "path"},
		{name: "url", env: map[string]string{"SIGNARI_FIDO_MDS_URL": "https://mirror.example/mds"}, want: "url", wantURL: "https://mirror.example/mds"},
		{name: "fetch", env: map[string]string{"SIGNARI_FIDO_MDS_FETCH": "1"}, want: "url"},
		{
			name: "path wins over url",
			env: map[string]string{
				"SIGNARI_FIDO_MDS_PATH": "/etc/mds.jwt",
				"SIGNARI_FIDO_MDS_URL":  "https://mirror.example/mds",
			},
			want: "path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string { return c.env[k] }
			r := NewFromEnv(getenv, quietLog())
			if c.wantNil {
				if r != nil {
					t.Fatalf("expected no resolver when no source is configured, got %+v", r.src)
				}
				return
			}
			if r == nil {
				t.Fatal("expected a resolver, got nil")
			}
			switch c.want {
			case "path":
				if r.src.path == "" || r.src.url != "" {
					t.Errorf("expected a file source, got %+v", r.src)
				}
			case "url":
				if r.src.url == "" || r.src.path != "" {
					t.Errorf("expected a url source, got %+v", r.src)
				}
				if c.wantURL != "" && r.src.url != c.wantURL {
					t.Errorf("url = %q, want %q", r.src.url, c.wantURL)
				}
			}
		})
	}
}

func TestReadFromFileReturnsTheBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mds.jwt")
	want := []byte("not a real blob, just bytes")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{src: source{path: path}, log: quietLog()}
	got, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}
}

// An unsigned or corrupt BLOB must be refused, AND the previously loaded
// catalogue must survive the failure -- a bad refresh should degrade to "the
// last good names" rather than "no names at all".
func TestRefreshRejectsAGarbageBlobAndKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mds.jwt")
	if err := os.WriteFile(path, []byte("this is not a signed JWT"), 0o600); err != nil {
		t.Fatal(err)
	}

	id := uuid.MustParse(yubi5)
	r := &Resolver{src: source{path: path}, log: quietLog()}
	// Seed a good table, as a prior successful refresh would have.
	seed := map[uuid.UUID]string{id: "YubiKey 5 NFC"}
	r.table.Store(&seed)
	r.loaded.Store(true)

	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh accepted a BLOB that is not a signed JWT")
	}
	// The old table is still in force.
	if got, ok := r.Model(id[:]); !ok || got != "YubiKey 5 NFC" {
		t.Errorf("a failed refresh discarded the previous catalogue: got %q ok=%v", got, ok)
	}
}

func TestRefreshReportsAMissingFile(t *testing.T) {
	r := &Resolver{src: source{path: filepath.Join(t.TempDir(), "absent.jwt")}, log: quietLog()}
	if err := r.Refresh(context.Background()); err == nil {
		t.Error("Refresh did not report a missing source file")
	}
}
