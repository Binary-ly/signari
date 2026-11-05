package httpapi

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"signari.dev/engine/internal/ratelimit"
	"signari.dev/engine/internal/safedial"
)

// Dynamic registration takes subject_type and sector_identifier_uri (9.07). A pairwise
// client whose redirect URIs name two hosts registers a document listing them, and its
// sector is the document's host; one with a single host takes that host. The document
// must hold every redirect URI exactly, be https, and be what it says it is. An update
// cannot move the redirect URIs out of the sector the client's subjects were made for,
// which would hand that sector's subjects to an address it never named.
func TestADynamicallyRegisteredClientNamesItsSector(t *testing.T) {
	f := newTokenFixture(t)
	f.srv.register = ratelimit.New(100, 100)
	ctx := context.Background()

	// Every refusal below is of a document that would otherwise pass, so each is
	// refused by the one rule it breaks: the plaintext one, the missing one and the
	// oversized one all list every redirect URI.
	const listed = `"https://a.rp.test/cb","https://b.rp.test/cb","https://solo.rp.test/new"`
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[`+listed+`]`)
	}))
	t.Cleanup(plaintext.Close)
	sectorSite := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/sector.json":
			_, _ = io.WriteString(w, `[`+listed+`]`)
		case "/gone.json":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `[`+listed+`]`)
		case "/object.json":
			_, _ = io.WriteString(w, `{"redirect_uris":[`+listed+`]}`)
		case "/big.json":
			_, _ = io.WriteString(w, `[`+listed+strings.Repeat(`,"https://x.rp.test/cb"`, 4000)+`]`)
		case "/moved":
			http.Redirect(w, r, plaintext.URL+"/sector.json", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(sectorSite.Close)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: sectorSite.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safedial.TrustBundle(bundle); err != nil {
		t.Fatal(err)
	}
	if err := safedial.AllowPrivate("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safedial.TrustBundle(""); _ = safedial.AllowPrivate("") })
	doc := sectorSite.URL + "/sector.json"

	send := func(method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = freshAddress() + ":443"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.srv.Routes().ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	token := registrationToken(t, f)
	register := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		return send(http.MethodPost, "/oauth2/register", token, body)
	}
	stored := func(clientID string) (kind, sector string) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT subject_type, sector FROM core.clients WHERE client_id = $1`,
			clientID).Scan(&kind, &sector); err != nil {
			t.Fatal(err)
		}
		return kind, sector
	}
	two := `"redirect_uris":["https://a.rp.test/cb","https://b.rp.test/cb"],"subject_type":"pairwise"`

	for name, body := range map[string]string{
		"an unknown subject type":                `{"redirect_uris":["https://a.rp.test/cb"],"subject_type":"secret"}`,
		"pairwise across two hosts, no document": `{` + two + `}`,
		"pairwise on loopback, no document":      `{"redirect_uris":["http://127.0.0.1:9000/cb"],"subject_type":"pairwise"}`,
		"a document over plaintext":              `{` + two + `,"sector_identifier_uri":"` + plaintext.URL + `/sector.json"}`,
		"a document missing a redirect": `{"redirect_uris":["https://a.rp.test/cb","https://c.rp.test/cb"],` +
			`"subject_type":"pairwise","sector_identifier_uri":"` + doc + `"}`,
		"a redirect listed in another case": `{"redirect_uris":["https://A.rp.test/cb"],"subject_type":"pairwise",` +
			`"sector_identifier_uri":"` + doc + `"}`,
		"a document that is not there":    `{` + two + `,"sector_identifier_uri":"` + sectorSite.URL + `/gone.json"}`,
		"a document that is not an array": `{` + two + `,"sector_identifier_uri":"` + sectorSite.URL + `/object.json"}`,
		"a document past the ceiling":     `{` + two + `,"sector_identifier_uri":"` + sectorSite.URL + `/big.json"}`,
		"a document that moves to http":   `{` + two + `,"sector_identifier_uri":"` + sectorSite.URL + `/moved"}`,
		"a document on a private address": `{` + two + `,"sector_identifier_uri":"https://10.0.0.1/sector.json"}`,
	} {
		if rec, out := register(body); rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: registered, answering %d %v", name, rec.Code, out)
		}
	}

	rec, made := register(`{` + two + `,"sector_identifier_uri":"` + doc + `"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering with a document: %d %s", rec.Code, rec.Body.String())
	}
	id, _ := made["client_id"].(string)
	if made["subject_type"] != "pairwise" || made["sector_identifier_uri"] != doc {
		t.Errorf("the registration answered %v; it must say what was registered", made)
	}
	if kind, sector := stored(id); kind != "pairwise" || sector != "127.0.0.1" {
		t.Errorf("stored %s in sector %q; the sector is the document's host", kind, sector)
	}

	rec, solo := register(`{"redirect_uris":["https://solo.rp.test/cb"],"subject_type":"pairwise"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering on one host: %d %s", rec.Code, rec.Body.String())
	}
	soloID, _ := solo["client_id"].(string)
	if kind, sector := stored(soloID); kind != "pairwise" || sector != "solo.rp.test" {
		t.Errorf("one host stored %s in sector %q", kind, sector)
	}

	rec, plain := register(`{"redirect_uris":["https://plain.rp.test/cb"]}`)
	if rec.Code != http.StatusCreated || plain["subject_type"] != "public" {
		t.Errorf("a client asking nothing answered %d %v; it is public and told so", rec.Code, plain)
	}

	update := func(made map[string]any, body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		id, _ := made["client_id"].(string)
		manage, _ := made["registration_access_token"].(string)
		return send(http.MethodPut, "/oauth2/register/"+id, manage, `{"client_id":"`+id+`",`+body+`}`)
	}
	redirects := func(clientID string) []string {
		t.Helper()
		rows, err := f.pool.Query(ctx, `SELECT redirect_uri FROM core.client_redirect_uris
			WHERE client_id = $1 ORDER BY redirect_uri`, clientID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err != nil {
				t.Fatal(err)
			}
			out = append(out, u)
		}
		return out
	}

	for name, tc := range map[string]struct {
		client map[string]any
		body   string
	}{
		"out of a document's sector":           {made, `"redirect_uris":["https://evil.test/cb"]`},
		"its own hosts, the document left out": {made, `"redirect_uris":["https://b.rp.test/cb"]`},
		"out of a host's sector":               {solo, `"redirect_uris":["https://evil.test/cb"]`},
		"a document on another host":           {solo, `"redirect_uris":["https://solo.rp.test/new"],"sector_identifier_uri":"` + doc + `"`},
		"a document without the new redirect":  {made, `"redirect_uris":["https://evil.test/cb"],"sector_identifier_uri":"` + doc + `"`},
	} {
		id, _ := tc.client["client_id"].(string)
		before := redirects(id)
		if rec, out := update(tc.client, tc.body); rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: updated, answering %d %v", name, rec.Code, out)
		}
		if after := redirects(id); strings.Join(after, " ") != strings.Join(before, " ") {
			t.Errorf("%s: refused and the redirect URIs moved anyway, %v to %v", name, before, after)
		}
	}

	if rec, out := update(made, `"redirect_uris":["https://b.rp.test/cb"],"sector_identifier_uri":"`+doc+`"`); rec.Code != http.StatusOK ||
		out["subject_type"] != "pairwise" {
		t.Errorf("an update the document vouches for answered %d %v", rec.Code, out)
	}
	if kind, sector := stored(id); kind != "pairwise" || sector != "127.0.0.1" {
		t.Errorf("after the update, %s in sector %q", kind, sector)
	}
	if rec, _ := update(solo, `"redirect_uris":["https://solo.rp.test/new"]`); rec.Code != http.StatusOK {
		t.Errorf("an update on the client's own host answered %d %s", rec.Code, rec.Body.String())
	}
	plainID, _ := plain["client_id"].(string)
	if rec, out := update(plain, `"redirect_uris":["https://plain.rp.test/cb"],"subject_type":"pairwise"`); rec.Code != http.StatusOK ||
		out["subject_type"] != "pairwise" {
		t.Errorf("turning pairwise by an update answered %d %v", rec.Code, out)
	}
	if kind, sector := stored(plainID); kind != "pairwise" || sector != "plain.rp.test" {
		t.Errorf("turned pairwise: %s in sector %q", kind, sector)
	}
	manage, _ := made["registration_access_token"].(string)
	if _, read := send(http.MethodGet, "/oauth2/register/"+id, manage, ""); read["subject_type"] != "pairwise" {
		t.Errorf("read back %v without its subject type", read)
	}
}
