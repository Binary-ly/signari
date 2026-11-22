package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"signari.dev/engine/internal/oidc"
	"signari.dev/engine/internal/tracing"
)

// spanAttributes are every attribute key a span may carry (3.09). A new one is
// a decision about what leaves this system, so it is added here by hand.
var spanAttributes = map[string]bool{
	"http.request.method": true, "http.route": true, "http.response.status_code": true,
	"db.system.name": true, "db.operation.name": true, "db.response.status_code": true,
	"code.function.name": true, "error.type": true,
}

// identifierish is what a value about a person or a credential looks like: the
// metrics package's pattern, plus a JWT and a long run of base64url.
var identifierish = regexp.MustCompile(
	`(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` +
		`|@[a-z0-9.-]+\.[a-z]{2,}` +
		`|\b\d{1,3}(\.\d{1,3}){3}\b` +
		`|[0-9a-f]{32,}` +
		`|eyJ[a-z0-9_-]+\.` +
		`|[a-z0-9_-]{40,})`)

// A person signs in to an application and the application redeems the code, and
// the spans that journey leaves are a tree a collector can draw, and say nothing
// about who it was: not the person, not the client, not the code or the tokens,
// not the address it came from.
func TestTheSignInIsTracedWithoutAnIdentifier(t *testing.T) {
	spans, stop := tracing.Capture()
	defer stop()
	f := newSignInFixture(t)

	req := httptest.NewRequest(http.MethodGet, oidc.PathAuthorize+"?"+f.plainAuthz(), nil)
	req.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	req.Header.Set("tracestate", "vendor="+f.email)
	page := httptest.NewRecorder()
	f.srv.Routes().ServeHTTP(page, req)
	if body := page.Body.String(); !strings.Contains(body, `name="password"`) {
		t.Fatalf("the authorization request answered %d: %.400s", page.Code, body[max(strings.Index(body, "<main"), 0):])
	}
	back, cookie := f.signInThrough(t, page)
	code := redirected(t, back).Get("code")
	tokens := f.redeemPlain(t, back)
	stop()

	got := spans.Spans()
	byID := map[string]tracing.Span{}
	for _, s := range got {
		byID[s.SpanID] = s
	}
	server := func(route string) tracing.Span {
		t.Helper()
		for _, s := range got {
			if s.Kind == tracing.KindServer && s.Attributes["http.route"] == route {
				return s
			}
		}
		t.Fatalf("no span for %s among %d", route, len(got))
		return tracing.Span{}
	}
	for _, route := range []string{oidc.PathAuthorize, "/login", oidc.PathToken} {
		s := server(route)
		if s.Parent != "" || s.Name != s.Attributes["http.request.method"]+" "+route {
			t.Errorf("%s: %q with parent %q", route, s.Name, s.Parent)
		}
		queries := 0
		for _, c := range got {
			if c.Parent == s.SpanID {
				if c.TraceID != s.TraceID || c.Attributes["db.system.name"] != "postgresql" ||
					!strings.Contains(c.Attributes["code.function.name"], ".") {
					t.Errorf("%s has a child %+v", route, c)
				}
				queries++
			}
		}
		if queries == 0 {
			t.Errorf("%s ran no query anybody can see", route)
		}
	}
	if links := server(oidc.PathAuthorize).Links; len(links) != 1 || links[0].TraceState != "" {
		t.Errorf("the caller's context: %+v", links)
	}

	secrets := []string{f.clientID, f.userID, f.email, f.orgID, cookie, code, signInTestPassword,
		"192.0.2.1", "https://rp.test/cb", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}
	for _, k := range []string{"access_token", "id_token", "refresh_token"} {
		if v, ok := tokens[k].(string); ok {
			secrets = append(secrets, v)
		}
	}
	for _, s := range got {
		texts := []string{s.Name, s.StatusDescription}
		for k, v := range s.Attributes {
			if !spanAttributes[k] {
				t.Errorf("%s carries %s, which is not one of the keys a span may", s.Name, k)
			}
			texts = append(texts, v)
		}
		for _, l := range s.Links {
			texts = append(texts, l.TraceState)
		}
		if s.Events != 0 {
			t.Errorf("%s has %d events", s.Name, s.Events)
		}
		for _, text := range texts {
			for _, secret := range secrets {
				if secret != "" && strings.Contains(text, secret) {
					t.Errorf("%s carries %q", s.Name, secret)
				}
			}
			for _, enc := range []string{url.QueryEscape(f.email), url.PathEscape(f.clientID)} {
				if strings.Contains(text, enc) {
					t.Errorf("%s carries %q", s.Name, enc)
				}
			}
			if m := identifierish.FindString(text); m != "" {
				t.Errorf("%s carries %q, which looks like an identifier", s.Name, m)
			}
		}
	}
}
