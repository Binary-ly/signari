package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/text/language"

	"signari.dev/engine/internal/store"
)

// A client's name in other languages (10.12, RFC 7591 section 2.2).

// The name tagged with a language the reader asked for, the nearest in that language, and
// the untagged one when there is none: never another language because it is nearest.
func TestTheClientIsNamedInTheReadersLanguage(t *testing.T) {
	names := map[string]string{"ja-Jpan-JP": "クライアント名", "pt-BR": "Meu Cliente", "de": "Mein Client"}
	tags := func(s ...string) []language.Tag {
		out := make([]language.Tag, 0, len(s))
		for _, x := range s {
			out = append(out, language.MustParse(x))
		}
		return out
	}
	for _, c := range []struct {
		name  string
		prefs []language.Tag
		want  string
	}{
		{"Japanese asked for by its language alone", tags("ja"), "クライアント名"},
		{"Portuguese, given in Brazilian Portuguese", tags("pt"), "Meu Cliente"},
		{"the first language asked for that it has", tags("fr", "de"), "Mein Client"},
		{"a language it has none in", tags("fr"), "My Client"},
		{"a related language is not the language", tags("nl"), "My Client"},
		{"nobody asked", nil, "My Client"},
	} {
		if got := pickClientName(names, c.prefs, "My Client"); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := pickClientName(nil, tags("ja"), "My Client"); got != "My Client" {
		t.Errorf("a client with no other names: %q", got)
	}
}

// Registered as client_name#<tag>, answered as the members it was sent as, read back by
// RFC 7592's read, replaced by its update, and refused when it cannot be stored.
func TestALocalizedNameIsRegisteredReadBackAndReplaced(t *testing.T) {
	f := newTokenFixture(t)
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

	for name, body := range map[string]string{
		"a tag that is not one":       `{"redirect_uris":["https://rp.test/cb"],"client_name#not a tag":"x"}`,
		"a name that is not a string": `{"redirect_uris":["https://rp.test/cb"],"client_name#de":7}`,
		"two spellings of one tag":    `{"redirect_uris":["https://rp.test/cb"],"client_name#de":"a","client_name#DE":"b"}`,
	} {
		if rec, out := send(http.MethodPost, "/oauth2/register", token, body); rec.Code != http.StatusBadRequest ||
			out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: %d %v, want 400 invalid_client_metadata", name, rec.Code, out)
		}
	}

	rec, made := send(http.MethodPost, "/oauth2/register", token, `{"redirect_uris":["https://rp.test/cb"],
		"client_name":"My Client","client_name#ja-Jpan-JP":"クライアント名","client_name#de":"Mein Client"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d %s", rec.Code, rec.Body.String())
	}
	if made["client_name#ja-Jpan-JP"] != "クライアント名" || made["client_name#de"] != "Mein Client" ||
		made["client_name"] != "My Client" {
		t.Errorf("the registration answered %v: RFC 7591 section 3.2.1 returns every registered member", made)
	}
	id, _ := made["client_id"].(string)
	manage, _ := made["registration_access_token"].(string)
	path := "/oauth2/register/" + id

	if _, read := send(http.MethodGet, path, manage, ""); read["client_name#ja-Jpan-JP"] != "クライアント名" ||
		read["client_name#de"] != "Mein Client" {
		t.Errorf("read back %v", read)
	}

	rec, out := send(http.MethodPut, path, manage, `{"client_id":"`+id+`","redirect_uris":["https://rp.test/cb"],
		"client_name":"My Client","client_name#ja-Jpan-JP":"新しい名前"}`)
	if rec.Code != http.StatusOK || out["client_name#ja-Jpan-JP"] != "新しい名前" {
		t.Fatalf("replacing: %d %v", rec.Code, out)
	}
	names, err := store.ClientNames(context.Background(), f.pool, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := names["de"]; kept || names["ja-Jpan-JP"] != "新しい名前" || len(names) != 1 {
		t.Errorf("after the update the client is named %v: an update replaces the metadata, so a name it "+
			"leaves out is gone", names)
	}
}

// The consent screen names the client in the reader's language when it has a name in
// it: asked by the application's ui_locales or by the browser, and untagged otherwise.
func TestTheConsentScreenNamesTheClientInTheReadersLanguage(t *testing.T) {
	f := newTokenFixture(t)
	ctx := context.Background()
	var orgID string
	if err := f.pool.QueryRow(ctx, `SELECT org_id::text FROM core.clients WHERE client_id = $1`, f.clientID).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetClientNames(ctx, f.pool, orgID, f.clientID, map[string]string{"ja": "日本語の名前"}); err != nil {
		t.Fatal(err)
	}
	c, err := f.srv.lookupClient(ctx, f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	page := func(target, acceptLanguage string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if acceptLanguage != "" {
			req.Header.Set("Accept-Language", acceptLanguage)
		}
		rec := httptest.NewRecorder()
		f.srv.renderConsent(rec, req, c, store.ConsentDecision{Missing: []string{"profile"}}, nil, "client_id=x")
		return rec.Body.String()
	}
	if got := page("/authorize?client_id=x&ui_locales=ja", ""); !strings.Contains(got, "日本語の名前") {
		t.Errorf("ui_locales=ja: the screen does not name the client in Japanese:\n%s", got)
	}
	if got := page("/authorize?client_id=x", "ja,en;q=0.5"); !strings.Contains(got, "日本語の名前") {
		t.Error("Accept-Language ja: the screen does not name the client in Japanese")
	}
	if got := page("/authorize?client_id=x", "en"); strings.Contains(got, "日本語の名前") ||
		!strings.Contains(got, c.DisplayName) {
		t.Error("an English reader is shown the Japanese name, or not the untagged one")
	}
}
