package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasskeyDeleteRequiresCSRF(t *testing.T) {
	f := newTokenFixture(t)
	id := seedCredential(t, f, "A")
	seedCredential(t, f, "B")
	cookie, _ := f.signedInCookies(t)

	// Session cookie present, CSRF absent — a cross-origin form post.
	req := httptest.NewRequest(http.MethodPost, "/account/passkeys/delete",
		strings.NewReader("id="+id))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("a passkey was removed by a request carrying no CSRF token; " +
			"stripping a factor is exactly what a cross-origin post would want")
	}
}
