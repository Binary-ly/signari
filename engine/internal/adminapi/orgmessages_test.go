package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

func TestAnOrganisationRewordsItsOwnMessages(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	org, other := newDriftOrg(t, s), newDriftOrg(t, s)
	list := "/admin/organizations/" + org + "/messages"
	one := list + "/en/login.heading"

	for path, bad := range map[string]map[string]any{
		list + "/en/login.haeding":  {"text": "Hi"},
		list + "/xx/login.heading":  {"text": "Hi"},
		list + "/en/common.minutes": {"text": "soon"},
		one:                         {"text": ""},
	} {
		rec := call(t, s, http.MethodPut, path, testToken, bad)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_message") {
			t.Errorf("%s answered %d: %s", path, rec.Code, rec.Body)
		}
	}
	if got, err := store.OrgMessages(ctx, s.db, org); err != nil || len(got) != 0 {
		t.Fatalf("a refused message was stored: %+v, %v", got, err)
	}

	rec := call(t, s, http.MethodPut, one, testToken, map[string]any{"text": "Welcome to Acme"})
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("rewording answered %d: %s", rec.Code, rec.Body)
	}
	if rec = call(t, s, http.MethodPut, one, testToken, map[string]any{"text": "Welcome back"}); rec.Code != http.StatusOK {
		t.Fatalf("rewording it again answered %d: %s", rec.Code, rec.Body)
	}
	read := call(t, s, http.MethodGet, list, testToken, nil)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"text":"Welcome back"`) ||
		strings.Contains(read.Body.String(), "Welcome to Acme") {
		t.Errorf("reading them back answered %d: %s", read.Code, read.Body)
	}

	mine := mintToken(t, s, "words-"+org, org, []string{ScopeConfigRead, ScopeOrganizationsWrite}, nil)
	if got := call(t, s, http.MethodPut, list+"/ar/login.heading", mine, map[string]any{"text": "مرحبا"}); got.Code != http.StatusOK {
		t.Errorf("a token of the organisation answered %d: %s", got.Code, got.Body)
	}
	theirs := "/admin/organizations/" + other + "/messages"
	if got := call(t, s, http.MethodPut, theirs+"/en/login.heading", mine, map[string]any{"text": "Theirs"}); got.Code != http.StatusForbidden {
		t.Errorf("a token of one organisation reworded another's: %d %s", got.Code, got.Body)
	}
	if got := call(t, s, http.MethodGet, theirs, mine, nil); got.Code != http.StatusForbidden {
		t.Errorf("a token of one organisation read another's: %d %s", got.Code, got.Body)
	}

	if got := call(t, s, http.MethodDelete, one, testToken, nil); got.Code != http.StatusOK {
		t.Fatalf("removing it answered %d: %s", got.Code, got.Body)
	}
	if got := call(t, s, http.MethodDelete, one, testToken, nil); got.Code != http.StatusNotFound {
		t.Errorf("removing nothing answered %d: %s", got.Code, got.Body)
	}
	if words, err := store.OrgWords(ctx, s.db, org, "en"); err != nil || len(words) != 0 {
		t.Errorf("the message survived: %+v, %v", words, err)
	}
	if words, _ := store.OrgWords(ctx, s.db, org, "ar"); words["login.heading"] != "مرحبا" {
		t.Errorf("removing one language took another: %+v", words)
	}
}
