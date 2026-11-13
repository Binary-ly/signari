package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// grantServer is a target whose token endpoint rotates refresh tokens and takes a
// spent one coming back as a stolen one, ending the grant, as OAuth 2.1 describes
// rotation (specs/draft-ietf-oauth-v2-1-17.txt:2660-2672).
type grantServer struct {
	*httptest.Server
	mu sync.Mutex
	// live is the refresh token that works; spent are those it replaced.
	live      string
	spent     map[string]bool
	ended     bool
	issued    int
	presented []string
	forms     []url.Values
	// keep has it answer without a new refresh token; tokenType is the access
	// token's type.
	keep      bool
	tokenType string
	// access is the access token the SCIM requests must carry.
	access string
	// codes are the codes a sign-in could have sent back, with the challenge and
	// redirect URI each was given for.
	codes map[string][2]string
}

func newGrantServer(t *testing.T) *grantServer {
	t.Helper()
	g := &grantServer{live: "rt-1", spent: map[string]bool{}, tokenType: "Bearer", codes: map[string][2]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.mu.Lock()
		defer g.mu.Unlock()
		g.forms = append(g.forms, r.PostForm)
		refuse := func(code string) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		id, secret, _ := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if id != "our client" || secret != "the secret" {
			refuse("invalid_client")
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			rt := r.PostForm.Get("refresh_token")
			g.presented = append(g.presented, rt)
			if g.spent[rt] {
				g.ended = true
			}
			if g.ended || rt != g.live {
				refuse("invalid_grant")
				return
			}
		case "authorization_code":
			given, ok := g.codes[r.PostForm.Get("code")]
			delete(g.codes, r.PostForm.Get("code"))
			if !ok || Challenge(r.PostForm.Get("code_verifier")) != given[0] ||
				r.PostForm.Get("redirect_uri") != given[1] {
				refuse("invalid_grant")
				return
			}
		default:
			refuse("unsupported_grant_type")
			return
		}
		g.issued++
		g.access = fmt.Sprintf("at-%d", g.issued)
		answer := map[string]any{"access_token": g.access, "token_type": g.tokenType, "expires_in": 3600}
		if !g.keep {
			g.spent[g.live] = true
			g.live = fmt.Sprintf("rt-%d", g.issued+1)
			answer["refresh_token"] = g.live
		}
		_ = json.NewEncoder(w).Encode(answer)
	})
	mux.HandleFunc("GET /Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+g.access {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.PathValue("id")})
	})
	g.Server = httptest.NewTLSServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *grantServer) target(held RefreshTokens) Target {
	return Target{BaseURL: g.URL, Token: "the secret", OAuthTokenURL: g.URL + "/token", OAuthClientID: "our client",
		OAuthScope: "scim.write", OAuthAuthorizeURL: "https://signin.example.test/authorize", Refresh: held}
}

// heldToken is RefreshTokens in memory, holding its lock while use runs as the
// database holds the row.
type heldToken struct {
	mu    sync.Mutex
	token string
}

func (h *heldToken) Rotate(_ context.Context, use func(string) (string, error)) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := use(h.token)
	if next != "" {
		h.token = next
	}
	return err
}

// Each pass asks with the refresh token the last one left and keeps the one it is
// given, so an authorization server that rotates them and ends a grant whose spent
// token comes back sees each token once.
func TestEachPassAsksWithTheRefreshTokenTheLastOneLeft(t *testing.T) {
	g := newGrantServer(t)
	held := &heldToken{token: "rt-1"}
	ctx := context.Background()
	for pass := range 3 {
		if _, err := NewClient(g.target(held), g.Client()).GetUser(ctx, "u-1"); err != nil {
			t.Fatalf("pass %d: %v", pass+1, err)
		}
	}
	if got := strings.Join(g.presented, ","); got != "rt-1,rt-2,rt-3" || g.ended {
		t.Errorf("the token endpoint was shown %s (grant ended: %v)", got, g.ended)
	}
	if held.token != "rt-4" {
		t.Errorf("%q is held, not the one last issued", held.token)
	}
	form := g.forms[0]
	// No scope, so the grant keeps what the person agreed to; no secret in the
	// form, which went by Basic.
	if form.Get("grant_type") != "refresh_token" || form.Has("scope") || form.Has("client_secret") {
		t.Errorf("asked with %v", form)
	}
}

// A token endpoint that issues no new refresh token leaves the one held good.
func TestARefreshTokenTheEndpointDoesNotReplaceStaysHeld(t *testing.T) {
	g := newGrantServer(t)
	g.keep = true
	held := &heldToken{token: "rt-1"}
	for range 2 {
		if _, err := NewClient(g.target(held), g.Client()).GetUser(context.Background(), "u-1"); err != nil {
			t.Fatal(err)
		}
	}
	if held.token != "rt-1" || strings.Join(g.presented, ",") != "rt-1,rt-1" {
		t.Errorf("held %q after showing %v", held.token, g.presented)
	}
}

// Once issued, the new refresh token is the only one: an answer refused for what
// else it says still leaves it held, or the next pass ends the grant.
func TestTheNewRefreshTokenIsKeptWhenTheRestOfTheAnswerIsRefused(t *testing.T) {
	g := newGrantServer(t)
	g.tokenType = "DPoP"
	held := &heldToken{token: "rt-1"}
	_, err := NewClient(g.target(held), g.Client()).GetUser(context.Background(), "u-1")
	if err == nil || !strings.Contains(err.Error(), "DPoP") {
		t.Fatalf("a DPoP token was taken: %v", err)
	}
	if held.token != "rt-2" {
		t.Errorf("%q is held, and the token endpoint has replaced it with rt-2", held.token)
	}
}

// A grant the authorization server has ended is said as such, with what to do.
func TestAnEndedGrantSaysToAuthorizeAgain(t *testing.T) {
	g := newGrantServer(t)
	g.ended = true
	_, err := NewClient(g.target(&heldToken{token: "rt-1"}), g.Client()).GetUser(context.Background(), "u-1")
	var refused *Error
	if !errors.As(err, &refused) || refused.OAuthError != "invalid_grant" ||
		!strings.Contains(err.Error(), "signari scim authorize") {
		t.Errorf("an ended grant failed with %v", err)
	}
}

// A target nobody has authorized asks nobody for anything.
func TestATargetNobodyAuthorizedAsksNobody(t *testing.T) {
	g := newGrantServer(t)
	_, err := NewClient(g.target(&heldToken{}), g.Client()).GetUser(context.Background(), "u-1")
	if !errors.Is(err, ErrNotAuthorized) || len(g.forms) != 0 {
		t.Errorf("answered %v after %d token requests", err, len(g.forms))
	}
	_, err = NewClient(g.target(nil), g.Client()).GetUser(context.Background(), "u-1")
	if err == nil || len(g.forms) != 0 {
		t.Errorf("with nowhere to keep a token it answered %v", err)
	}
}

// The authorization URL keeps the query it was given, sets what the request needs
// over anything there of the same name, and asks for S256.
func TestTheAuthorizationURLKeepsItsQueryAndAsksForS256(t *testing.T) {
	tg := Target{OAuthAuthorizeURL: "https://signin.example.test/authorize?tenant=acme&response_type=token",
		OAuthClientID: "our client", OAuthScope: "scim.write offline_access"}
	got, err := AuthorizationURL(tg, "http://127.0.0.1:5123/callback", "the-state", "the-verifier")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	want := map[string]string{"tenant": "acme", "response_type": "code", "client_id": "our client",
		"redirect_uri": "http://127.0.0.1:5123/callback", "state": "the-state", "scope": "scim.write offline_access",
		"code_challenge": Challenge("the-verifier"), "code_challenge_method": "S256"}
	for k, v := range want {
		if q.Get(k) != v || len(q[k]) != 1 {
			t.Errorf("%s is %v, want %q", k, q[k], v)
		}
	}
	if q.Has("code_verifier") || strings.Contains(got, "the-verifier") {
		t.Errorf("the verifier left: %s", got)
	}
	// RFC 7636 Appendix B's own example (specs/rfc7636.txt:942, 962).
	if c := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); c != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("the S256 challenge of the RFC's verifier is %s", c)
	}
	tg.OAuthAuthorizeURL = "https://signin.example.test/authorize#fragment"
	if _, err := AuthorizationURL(tg, "https://console.example.test/cb", "s", "v"); err == nil {
		t.Error("an authorization URL with a fragment was used")
	}
}

// A code is redeemed with the redirect URI it was sent to and the verifier whose
// challenge went with it, and an answer with no refresh token is refused.
func TestACodeIsRedeemedWithItsRedirectAndVerifier(t *testing.T) {
	g := newGrantServer(t)
	tg := g.target(nil)
	g.codes["the-code"] = [2]string{Challenge("the-verifier"), "http://127.0.0.1:5123/callback"}
	refresh, err := ExchangeCode(context.Background(), g.Client(), tg, "the-code", "http://127.0.0.1:5123/callback",
		"the-verifier")
	if err != nil || refresh != "rt-2" {
		t.Fatalf("redeemed for %q, %v", refresh, err)
	}
	if f := g.forms[0]; f.Get("grant_type") != "authorization_code" || f.Get("code_verifier") != "the-verifier" {
		t.Errorf("redeemed with %v", f)
	}

	g.codes["another"] = [2]string{Challenge("the-verifier"), "http://127.0.0.1:5123/callback"}
	if _, err := ExchangeCode(context.Background(), g.Client(), tg, "another", "http://127.0.0.1:9999/callback",
		"the-verifier"); err == nil {
		t.Error("a code was redeemed with a redirect URI it was not sent to")
	}

	g.keep = true
	g.codes["a-third"] = [2]string{Challenge("the-verifier"), "http://127.0.0.1:5123/callback"}
	if _, err := ExchangeCode(context.Background(), g.Client(), tg, "a-third", "http://127.0.0.1:5123/callback",
		"the-verifier"); err == nil || !strings.Contains(err.Error(), "no refresh token") {
		t.Errorf("an answer with no refresh token gave %v", err)
	}
}

// A code comes back over https, or to a loopback address by its number.
func TestOnlyAnHTTPSOrLoopbackRedirectIsTaken(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://console.example.test/scim/callback": true,
		"http://127.0.0.1:5123/callback":             true,
		"http://[::1]:5123/callback":                 true,
		"http://localhost:5123/callback":             false,
		"http://console.example.test/callback":       false,
		"https://console.example.test/cb#x":          false,
		"/callback":                                  false,
	} {
		if err := CheckRedirectURI(raw); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
