package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentilesAreNearestRank(t *testing.T) {
	var lat []time.Duration
	for i := 1; i <= 100; i++ {
		lat = append(lat, time.Duration(i)*time.Millisecond)
	}
	for p, want := range map[int]time.Duration{50: 50, 95: 95, 99: 99, 100: 100, 1: 1} {
		if got := percentile(lat, p); got != want*time.Millisecond {
			t.Errorf("p%d = %s, want %s", p, got, want*time.Millisecond)
		}
	}
	if got := percentile([]time.Duration{7}, 99); got != 7 {
		t.Errorf("p99 of one sample = %s", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("p50 of nothing = %s", got)
	}
}

// The RFC 7636 Appendix B pair, as engine/internal/oauth/pkce_test.go holds it.
func TestThePKCEChallengeIsS256(t *testing.T) {
	if got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge = %s", got)
	}
}

// The request decodes the way the engine's server decodes one: the password
// comes back from the MD5 keystream, and the Message-Authenticator is the
// HMAC of the packet with that field zeroed.
func TestAnAccessRequestIsWhatARADIUSServerReads(t *testing.T) {
	const secret = "a-sufficiently-long-shared-secret"
	var auth [16]byte
	copy(auth[:], "0123456789abcdef")
	for _, password := range []string{"short", "exactly-sixteen!", "a password longer than one block"} {
		pkt := accessRequest(secret, "alice", password, 42, auth)
		if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) || pkt[0] != radiusAccessRequest || pkt[1] != 42 {
			t.Fatalf("%q: header %x", password, pkt[:4])
		}
		attrs := map[byte][]byte{}
		for i := 20; i < len(pkt); i += int(pkt[i+1]) {
			attrs[pkt[i]] = pkt[i+2 : i+int(pkt[i+1])]
		}
		if string(attrs[attrUserName]) != "alice" {
			t.Errorf("User-Name is %q", attrs[attrUserName])
		}
		// Reverse the hiding, as engine/internal/radius DecodePassword does.
		ct, prev, out := attrs[attrUserPassword], auth[:], []byte{}
		for i := 0; i < len(ct); i += 16 {
			h := md5.New()
			h.Write([]byte(secret))
			h.Write(prev)
			key := h.Sum(nil)
			for j := 0; j < 16; j++ {
				out = append(out, ct[i+j]^key[j])
			}
			prev = ct[i : i+16]
		}
		if got := strings.TrimRight(string(out), "\x00"); got != password {
			t.Errorf("the password decodes to %q, want %q", got, password)
		}
		zeroed := append([]byte(nil), pkt...)
		copy(zeroed[22:38], make([]byte, 16))
		mac := hmac.New(md5.New, []byte(secret))
		mac.Write(zeroed)
		if !hmac.Equal(mac.Sum(nil), attrs[attrMessageAuth]) {
			t.Errorf("%q: the Message-Authenticator does not verify", password)
		}
	}
}

// The login and consent forms as the engine renders them: hidden fields are
// unescaped, the visible ones present and empty, the decision chosen by the
// caller.
func TestTheSignInFormsAreRead(t *testing.T) {
	login := `<form method="POST" action="/login">
<input type="hidden" name="authz" value="client_id=x&amp;state=y">
<input type="hidden" name="csrf_token" value="tok">
<input id="u" name="username" autocomplete="username webauthn" required>
<input id="p" name="password" type="password" required>
<button type="submit">Sign in</button></form>`
	action, f, ok := parseForm(login)
	if !ok || action != "/login" || f.Get("authz") != "client_id=x&state=y" || f.Get("csrf_token") != "tok" ||
		!f.Has("username") || !f.Has("password") {
		t.Errorf("login form read as %q %v %v", action, f, ok)
	}
	consent := `<form method="POST" action="/consent"><input type="hidden" name="authz" value="a">
<input type="hidden" name="scope" value="openid"><input type="hidden" name="scope" value="email">
<button class="deny" type="submit" name="decision" value="deny">No</button>
<button class="allow" type="submit" name="decision" value="allow">Yes</button></form>`
	_, f, _ = parseForm(consent)
	if !f.Has("decision") || len(f["scope"]) != 2 {
		t.Errorf("consent form read as %v", f)
	}
	if _, _, ok := parseForm("<p>no form here</p>"); ok {
		t.Error("a page without a form was read as one")
	}
}

// fakeProvider answers discovery, the token endpoint, introspection, and a
// login form that issues a code, which is enough to drive every HTTP scenario
// that needs no directory.
func fakeProvider(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	var refreshes atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"introspection_endpoint": srv.URL + "/introspect", "jwks_uri": srv.URL + "/jwks",
			"userinfo_endpoint": srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) })
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?"+url.Values{"authz": {r.URL.RawQuery}}.Encode(), http.StatusSeeOther)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="POST" action="/login"><input type="hidden" name="authz" value="` +
			strings.ReplaceAll(r.URL.Query().Get("authz"), "&", "&amp;") + `"><input name="username"><input name="password" type="password"></form>`))
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("username") != "alice" || r.Form.Get("password") != "pw" {
			http.Error(w, "wrong", http.StatusUnauthorized)
			return
		}
		authz, _ := url.ParseQuery(r.Form.Get("authz"))
		http.Redirect(w, r, "/consent", http.StatusSeeOther)
		_ = authz
	})
	mux.HandleFunc("GET /consent", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<form method="POST" action="/consent"><button name="decision" value="deny">n</button></form>`))
	})
	mux.HandleFunc("POST /consent", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("decision") != "allow" {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		// The state is echoed from the original request, which the fake keeps
		// in a cookie the way a real one keeps it server side.
		c, _ := r.Cookie("state")
		http.Redirect(w, r, "https://bench.invalid/cb?code=c1&state="+c.Value, http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// Decoded as the engine decodes Basic credentials (form-urlencoded
		// inside), so a '+' in the secret proves the driver encodes it.
		id, secret, ok := r.BasicAuth()
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if !ok || id != "bench" || secret != "s+1" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "client_credentials":
			_, _ = w.Write([]byte(`{"access_token":"at"}`))
		case "authorization_code":
			if r.Form.Get("code") != "c1" || pkceChallenge(r.Form.Get("code_verifier")) == "" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt0"}`))
		case "refresh_token":
			n := refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "refresh_token": "rt" + string(rune('0'+n%10))})
		}
	})
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"active":true}`))
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"sub":"alice"}`))
	})
	// Remember the authorization request's state for the consent redirect.
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/authorize" {
			http.SetCookie(w, &http.Cookie{Name: "state", Value: r.URL.Query().Get("state"), Path: "/"})
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every HTTP scenario runs against the fake for a moment, with no errors, and
// reports what it measured.
func TestTheHTTPScenariosMeasureAProvider(t *testing.T) {
	srv := fakeProvider(t)
	c := &config{Issuer: srv.URL, ClientID: "bench", ClientSecret: "s+1",
		RedirectURI: "https://bench.invalid/cb", Scope: "openid offline_access",
		Username: "alice", Password: "pw", Concurrency: 2, Duration: 150 * time.Millisecond}
	for _, name := range []string{"discovery", "jwks", "client-credentials", "introspect", "signin", "refresh", "userinfo"} {
		res, err := measure(context.Background(), c, name, scenarios[name])
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if res.Ops == 0 || res.Errors != 0 || res.P99ms < res.P50ms || res.Target != srv.URL {
			t.Errorf("%s measured %+v", name, res)
		}
	}

	// A wrong password is an error, not a result: the scenario reports it
	// rather than timing the refusal as if it were a sign-in.
	bad := *c
	bad.Password = "wrong"
	if res, err := measure(context.Background(), &bad, "signin", scenarios["signin"]); err != nil || res.Ops != 0 || res.Errors == 0 ||
		!strings.Contains(res.FirstError, "401") {
		t.Errorf("a wrong password measured %+v, %v", res, err)
	}
	// A 429 is load shed, counted apart: it is the server working.
	shedding := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
	}))
	t.Cleanup(shedding.Close)
	sc := scenario{worker: func(_ context.Context, e *env) (func(context.Context) error, error) {
		hc := httpClient(e.cfg)
		return func(ctx context.Context) error { _, err := get(ctx, hc, shedding.URL, ""); return err }, nil
	}}
	if res, err := measure(context.Background(), c, "shed", sc); err != nil || res.Shed == 0 || res.Errors != 0 {
		t.Errorf("429s measured %+v, %v", res, err)
	}
	// A worker that cannot be set up fails the scenario outright.
	if _, err := measure(context.Background(), &bad, "refresh", scenarios["refresh"]); err == nil {
		t.Error("a refresh chain started from a refused sign-in")
	}
}
