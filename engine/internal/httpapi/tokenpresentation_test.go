package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnAccessTokenInTheQueryStringIsIgnored(t *testing.T) {
	const tok = "query-string-token"

	t.Run("GET with the token only in the query", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/userinfo?access_token="+tok, nil)
		if got, scheme := bearerTokenAndScheme(r); got != "" || scheme != "" {
			t.Errorf("read %q (scheme %q) out of the query string", got, scheme)
		}
	})

	t.Run("POST with the token only in the query", func(t *testing.T) {
		// A urlencoded POST, so ParseForm runs and r.Form gains the query value.
		// Reading r.Form instead of r.PostForm here would accept it.
		r := httptest.NewRequest(http.MethodPost, "/userinfo?access_token="+tok,
			strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if got, _ := bearerTokenAndScheme(r); got != "" {
			t.Errorf("read %q from the query string on a POST; ParseForm merges the "+
				"query into r.Form, so this is r.Form being read where r.PostForm "+
				"was meant", got)
		}
	})

	t.Run("query value cannot override a header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/userinfo?access_token=attacker", nil)
		r.Header.Set("Authorization", "Bearer real-token")
		got, scheme := bearerTokenAndScheme(r)
		if got != "real-token" || scheme != "Bearer" {
			t.Errorf("got %q/%q, want the header's token", got, scheme)
		}
	})
}

// The presentations that ARE permitted, so the test above cannot pass merely
// because nothing is ever accepted.
func TestThePermittedPresentationsStillWork(t *testing.T) {
	t.Run("Bearer header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		r.Header.Set("Authorization", "Bearer abc")
		if got, scheme := bearerTokenAndScheme(r); got != "abc" || scheme != "Bearer" {
			t.Errorf("got %q/%q", got, scheme)
		}
	})

	// RFC 9449 §7.1: a sender-constrained token is presented under the DPoP
	// scheme. Accepting only Bearer would make every bound token unusable at the
	// endpoint that enforces the binding.
	t.Run("DPoP header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		r.Header.Set("Authorization", "DPoP abc")
		if got, scheme := bearerTokenAndScheme(r); got != "abc" || scheme != "DPoP" {
			t.Errorf("got %q/%q", got, scheme)
		}
	})

	// OIDC Core §5.3.1 requires the POST form field.
	t.Run("POST form body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/userinfo",
			strings.NewReader("access_token=abc"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if got, scheme := bearerTokenAndScheme(r); got != "abc" || scheme != "Bearer" {
			t.Errorf("got %q/%q", got, scheme)
		}
	})

	// Two presentations at once is ambiguous by construction: a check could read
	// one and the logic use the other.
	t.Run("header and body together are refused", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/userinfo",
			strings.NewReader("access_token=body"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer header")
		if got, _ := bearerTokenAndScheme(r); got != "" {
			t.Errorf("resolved an ambiguous request to %q", got)
		}
	})
}
