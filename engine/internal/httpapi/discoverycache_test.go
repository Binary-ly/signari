package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/store"
)

// The discovery document costs one read of the version once it is built, answers a
// conditional request with nothing, and follows what it says on the next request: a change
// to the configuration, and a key this process comes to hold (E.07).
func TestDiscoveryIsBuiltOnlyWhenWhatItSaysChanges(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	fetch := func(etag string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, oidc.PathDiscovery, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	first := fetch("")
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || etag == "" || first.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("the document: %d %q %q", first.Code, etag, first.Header().Get("Content-Type"))
	}
	if rec := fetch(etag); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("a conditional request: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if rec := fetch(`"something else"`); rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Errorf("a stale ETag: %d, %d bytes", rec.Code, rec.Body.Len())
	}

	// rebuiltBetween reports whether the second of two reads built a new document. One
	// allocation is one document. Other packages move the version under this test, so
	// a pair the version moved across says nothing and is taken again.
	version := func() int64 {
		t.Helper()
		v, err := store.CurrentConfigVersion(ctx, f.pool)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	doc := func() *byte {
		t.Helper()
		body, _, err := f.srv.discoveryDocument(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return &body[0]
	}
	rebuiltBetween := func(change func()) bool {
		t.Helper()
		for range 50 {
			before := version()
			a := doc()
			change()
			b := doc()
			if version() == before {
				return a != b
			}
		}
		t.Skip("the version never held still for two reads")
		return false
	}

	if rebuiltBetween(func() {}) {
		t.Error("the document was built again with nothing having moved")
	}

	// The version moves, and the very next read follows it.
	var moved *byte
	for range 50 {
		a := doc()
		if _, err := f.pool.Exec(ctx, `UPDATE core.config_version SET version = version + 1, bumped_at = now()`); err != nil {
			t.Fatal(err)
		}
		if moved = doc(); moved != a {
			break
		}
		moved = nil
	}
	if moved == nil {
		t.Error("a new version did not rebuild the document")
	}

	// A key this process comes to hold moves no version, and is said too.
	signs := func() []string {
		t.Helper()
		var doc struct {
			Algs []string `json:"id_token_signing_alg_values_supported"`
		}
		if err := json.Unmarshal(fetch("").Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Algs
	}
	if slices.Contains(signs(), "RS256") {
		t.Fatal("the fixture already holds RS256")
	}
	k, err := keys.Generate(keys.NewKID(), keys.RS256)
	if err != nil {
		t.Fatal(err)
	}
	active, err := keys.WithState(k, keys.StateActive)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.cfg.Keys.Replace(append(f.srv.cfg.Keys.Keys(), active)...); err != nil {
		t.Fatal(err)
	}
	if got := signs(); !slices.Contains(got, "RS256") {
		t.Errorf("a new algorithm did not reach the document: %v", got)
	}
}
