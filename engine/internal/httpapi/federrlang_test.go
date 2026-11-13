package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"signari.dev/engine/internal/store"
)

// A refusal at an upstream sign-in is said in the reader's language. It used to be an
// English sentence for everybody, and a store error's own text could reach the page.
func TestAnUpstreamSignInRefusalIsSaidInTheReadersLanguage(t *testing.T) {
	f := newSignInFixture(t)
	for lang, want := range map[string]string{
		"ar": "بدأ تسجيل الدخول هذا في متصفح آخر",
		"en": "This sign-in was started in a different browser",
	} {
		r := httptest.NewRequest(http.MethodGet, "/login/with/x/callback", nil)
		r.Header.Set("Accept-Language", lang)
		rec := httptest.NewRecorder()
		f.srv.federationRefusal(rec, r, federatedLoginRefusal(store.ErrFederatedLoginOtherBrowser))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d, want %q in %s", lang, rec.Code, want, truncate(rec.Body.String(), 400))
		}
	}
}

// What a sign-in coming back can be refused for maps to a message, never to the
// error's text: a database error would otherwise be printed for whoever followed the
// link.
func TestAFederatedLoginErrorMapsToAMessage(t *testing.T) {
	for err, want := range map[error]string{
		store.ErrFederatedLoginGone:                               "federr.linkused",
		store.ErrFederatedLoginOtherBrowser:                       "federr.otherbrowser",
		errors.New("pq: could not serialize access"):              "federr.generic",
		errors.Join(errors.New("x"), store.ErrFederatedLoginGone): "federr.linkused",
	} {
		if got := federatedLoginRefusal(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}
