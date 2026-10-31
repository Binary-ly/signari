package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// checkableProvider publishes discovery and a JWKS, what each holds set by the test.
func checkableProvider(t *testing.T, edit func(doc map[string]any), keys string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
				"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys"}
			if edit != nil {
				edit(doc)
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/keys":
			_, _ = w.Write([]byte(keys))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const oneKey = `{"keys":[{"kty":"EC","crv":"P-256","kid":"a","use":"sig",
	"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`

func TestACheckSaysWhereAProviderStops(t *testing.T) {
	ctx := context.Background()
	good := checkableProvider(t, nil, oneKey)
	r := Config{IssuerOverride: good.URL}.Check(ctx, good.Client())
	if !r.OK || r.Keys != 1 {
		t.Fatalf("a working provider: %+v", r)
	}

	if r := (Config{IssuerOverride: good.URL + "/not-the-issuer"}).Check(ctx, good.Client()); r.OK || r.Step != "discovery" {
		t.Errorf("a mistyped issuer: %+v", r)
	}
	other := checkableProvider(t, func(d map[string]any) { d["issuer"] = "https://somebody-else.test" }, oneKey)
	if r := (Config{IssuerOverride: other.URL}).Check(ctx, other.Client()); r.OK || r.Step != "discovery" ||
		!strings.Contains(r.Detail, "somebody-else") {
		t.Errorf("a document claiming another issuer: %+v", r)
	}
	if r := (Config{IssuerOverride: good.URL, TokenOverride: good.URL + "/old-token"}).Check(ctx, good.Client()); r.OK ||
		r.Step != "endpoints" || !strings.Contains(r.Detail, "token endpoint") {
		t.Errorf("an endpoint that has moved: %+v", r)
	}
	empty := checkableProvider(t, nil, `{"keys":[]}`)
	if r := (Config{IssuerOverride: empty.URL}).Check(ctx, empty.Client()); r.OK || r.Step != "keys" {
		t.Errorf("no keys: %+v", r)
	}
	broken := checkableProvider(t, nil, `not json`)
	if r := (Config{IssuerOverride: broken.URL}).Check(ctx, broken.Client()); r.OK || r.Step != "keys" {
		t.Errorf("keys that do not parse: %+v", r)
	}
	if r := (Config{}).Check(ctx, good.Client()); !r.OK || r.Detail == "" {
		t.Errorf("a provider with nothing to ask: %+v", r)
	}
}
