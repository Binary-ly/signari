package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"signari.dev/engine/internal/keys"
	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/ratelimit"
)

// A key-set fetch the limit refuses is a refusal the client can read (0.110). The
// compressed form's Content-Encoding used to be set before the limit was asked, so once
// the set passed compressFrom every 429 was plain JSON labelled gzip: 3,341,641 of them
// in one benchmark, each read by the client as "gzip: invalid header". Three keys, as a
// set holds during a rotation, which is when relying parties refetch at once.
func TestARefusedKeySetFetchIsReadable(t *testing.T) {
	var held []keys.Key
	for _, k := range []struct {
		alg   keys.Algorithm
		state keys.State
	}{{keys.ES256, keys.StateActive}, {keys.RS256, keys.StateActive}, {keys.RS256, keys.StatePassive}} {
		made, err := keys.Generate(keys.NewKID(), k.alg)
		if err != nil {
			t.Fatal(err)
		}
		withState, err := keys.WithState(made, k.state)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, withState)
	}
	set, err := keys.NewSet(held...)
	if err != nil {
		t.Fatal(err)
	}
	// One fetch allowed, then none: the second is the refusal.
	srv := &Server{cfg: oidc.Config{Keys: set}, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		jwks: ratelimit.New(0, 1)}
	fetch := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
		r.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		srv.handleJWKS(rec, r)
		return rec
	}

	served := fetch()
	if served.Code != http.StatusOK || served.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("the set was served %d with Content-Encoding %q: too small to be compressed, so this proves nothing",
			served.Code, served.Header().Get("Content-Encoding"))
	}
	if got := gunzip(t, served.Body.Bytes()); !json.Valid(got) {
		t.Fatalf("the compressed set is not JSON once read: %.80q", got)
	}

	refused := fetch()
	if refused.Code != http.StatusTooManyRequests {
		t.Fatalf("the second fetch was answered %d, want 429", refused.Code)
	}
	if coding := refused.Header().Get("Content-Encoding"); coding != "" {
		t.Errorf("the refusal says Content-Encoding %q over a body that is not encoded", coding)
	}
	var said struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(refused.Body.Bytes(), &said); err != nil || said.Error != "rate_limited" {
		t.Errorf("the refusal cannot be read as what it is: %v, %.80q", err, refused.Body.String())
	}
	if refused.Header().Get("Retry-After") == "" {
		t.Error("the refusal does not say when to come back")
	}
}
