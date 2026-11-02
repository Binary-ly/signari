package cimd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAClientIdentifierURLIsHeldToSection3(t *testing.T) {
	for _, good := range []string{"https://app.example/client.json", "https://app.example:8443/a/b", "https://app.example/?x=1"} {
		if err := CheckURL(good); err != nil {
			t.Errorf("%s was refused: %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://app.example/client.json",
		"https://user:pass@app.example/client.json",
		"https://app.example",
		"https://app.example/a/../b",
		"https://app.example/./b",
		"https://app.example/%2e%2e/b",
		"https://app.example/client.json#frag",
		"https:///client.json",
	} {
		if err := CheckURL(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// site is the far end, and what it has been asked.
type site struct {
	*httptest.Server
	hits   atomic.Int32
	answer func(w http.ResponseWriter, r *http.Request, self string)
}

func newSite(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, self string)) *site {
	t.Helper()
	s := &site{answer: answer}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.answer(w, r, s.URL)
	}))
	t.Cleanup(s.Close)
	return s
}

func document(self string, change map[string]any) []byte {
	doc := map[string]any{"client_id": self + "/client.json", "client_name": "An application",
		"redirect_uris": []string{self + "/callback", "http://127.0.0.1:8123/callback"}}
	for name, value := range change {
		if value == nil {
			delete(doc, name)
			continue
		}
		doc[name] = value
	}
	body, _ := json.Marshal(doc)
	return body
}

func serving(change map[string]any) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document(self, change))
	}
}

func TestASoundDocumentIsRead(t *testing.T) {
	s := newSite(t, serving(nil))
	doc, keep, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Name != "An application" || doc.AuthMethod != AuthNone || len(doc.RedirectURIs) != 2 {
		t.Errorf("%+v", doc)
	}
	if keep != defaultLifetime {
		t.Errorf("kept for %v", keep)
	}
}

// Each thing §3, §4 and §4.1 rule out, and what §8.1 lets a server refuse.
func TestWhatADocumentMayNotSay(t *testing.T) {
	for name, change := range map[string]map[string]any{
		"another client's id":            {"client_id": "https://somebody.else/client.json"},
		"a shared secret":                {"client_secret": "hunter2"},
		"a secret's expiry":              {"client_secret_expires_at": 0},
		"a secret-based method":          {"token_endpoint_auth_method": "client_secret_basic"},
		"a jwt over a secret":            {"token_endpoint_auth_method": "client_secret_jwt"},
		"a key-based method with no key": {"token_endpoint_auth_method": "private_key_jwt"},
		"no redirect":                    {"redirect_uris": nil},
		"another site's redirect":        {"redirect_uris": []string{"https://evil.test/callback"}},
		"an http redirect off loopback":  {"redirect_uris": []string{"http://192.0.2.1/callback"}},
		"a grant it may not have":        {"grant_types": []string{"client_credentials"}},
		"no code grant":                  {"grant_types": []string{"refresh_token"}},
		"an implicit response":           {"response_types": []string{"token"}},
	} {
		s := newSite(t, serving(change))
		if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// §8.7: "stopping after a maximum number of bytes and treating the response as an error".
func TestAnOversizedDocumentIsAnError(t *testing.T) {
	s := newSite(t, serving(map[string]any{"client_name": strings.Repeat("a", MaxDocumentBytes)}))
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
		t.Error("it was read")
	}
	// Cut off at the limit this one is still good JSON, so only counting refuses it.
	s.answer = func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(document(self, nil), strings.Repeat(" ", MaxDocumentBytes)...))
	}
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
		t.Error("a document padded past the limit was read")
	}
}

// §5: "MUST NOT automatically follow HTTP redirects", and only a 200 will do.
func TestOnlyAStraight200IsADocument(t *testing.T) {
	s := newSite(t, nil)
	s.answer = func(w http.ResponseWriter, r *http.Request, self string) {
		if r.URL.Path == "/elsewhere" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(document(self, nil))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
		t.Error("a redirect was followed")
	}
	if got := s.hits.Load(); got != 1 {
		t.Errorf("%d requests", got)
	}
	s.answer = func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(http.StatusNotFound) }
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
		t.Error("a 404 was read")
	}
	s.answer = func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(document(self, nil))
	}
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err == nil {
		t.Error("an HTML page was read")
	}
	s.answer = func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Content-Type", "application/client-metadata+json")
		_, _ = w.Write(document(self, nil))
	}
	if _, _, err := Fetch(context.Background(), s.Client(), s.URL+"/client.json"); err != nil {
		t.Errorf("§4's application/<AS-defined>+json was refused: %v", err)
	}
}

func TestHowLongADocumentIsKept(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"":                      defaultLifetime,
		"max-age=600":           10 * time.Minute,
		"public, max-age=600":   10 * time.Minute,
		"max-age=1":             minLifetime,
		"max-age=99999999":      maxLifetime,
		"no-store":              minLifetime,
		"no-cache, max-age=600": minLifetime,
		"max-age=soon":          defaultLifetime,
	} {
		if got := lifetime(http.Header{"Cache-Control": {header}}); got != want {
			t.Errorf("%q kept for %v, want %v", header, got, want)
		}
	}
}

func TestAKeySetIsPublicKeysOnly(t *testing.T) {
	public := `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`
	private := strings.Replace(public, `"kty"`, `"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","kty"`, 1)
	symmetric := `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`
	s := newSite(t, nil)
	serve := func(body string) {
		s.answer = func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}
	ctx := context.Background()
	doc := Document{JWKS: json.RawMessage(public)}
	if _, err := doc.Keys(ctx, s.Client()); err != nil {
		t.Errorf("a public key was refused: %v", err)
	}
	for name, set := range map[string]string{"private": private, "symmetric": symmetric, "empty": `{"keys":[]}`} {
		doc := Document{JWKS: json.RawMessage(set)}
		if _, err := doc.Keys(ctx, s.Client()); err == nil {
			t.Errorf("a %s key set was taken", name)
		}
	}
	serve(public)
	byURL := Document{JWKSURI: s.URL + "/jwks"}
	if got, err := byURL.Keys(ctx, s.Client()); err != nil || !strings.Contains(string(got), "P-256") {
		t.Errorf("%s, %v", got, err)
	}
	serve(private)
	if _, err := byURL.Keys(ctx, s.Client()); err == nil {
		t.Error("a private key was taken from a jwks_uri")
	}
	insecure := Document{JWKSURI: "http://app.example/jwks"}
	if _, err := insecure.Keys(ctx, s.Client()); err == nil {
		t.Error("an http jwks_uri was followed")
	}
}
