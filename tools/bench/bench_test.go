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
	"sync"
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
// A run carries on taking turns where the last stopped, so that run after run nobody is taken
// twice before everybody has been once: a TOTP code replayed inside its 30 seconds is refused.
func TestTurnsCarryOnFromTheLastRun(t *testing.T) {
	path := t.TempDir() + "/turns"
	nextPerson.Store(0)
	save := resumeTurns(path) // no file yet: the start
	if got := nextPerson.Load(); got != 0 {
		t.Fatalf("a first run starts at %d", got)
	}
	nextPerson.Add(41)
	save()
	nextPerson.Store(0) // the next run is another process
	defer resumeTurns(path)()
	if got := nextPerson.Load(); got != 41 {
		t.Fatalf("the next run starts at %d, not where the last stopped (41)", got)
	}
	nextPerson.Store(0)
}

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
			"userinfo_endpoint": srv.URL + "/userinfo", "revocation_endpoint": srv.URL + "/revoke",
			"pushed_authorization_request_endpoint": srv.URL + "/par",
			"device_authorization_endpoint":         srv.URL + "/device",
			"backchannel_authentication_endpoint":   srv.URL + "/backchannel",
			"end_session_endpoint":                  srv.URL + "/logout",
		})
	})
	mux.HandleFunc("POST /backchannel", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if !strings.HasSuffix(r.Form.Get("login_hint"), "@"+benchDomain) {
			http.Error(w, `{"error":"unknown_user_id"}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"auth_req_id":"r1","expires_in":120}`))
	})
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id_token_hint") != "it" {
			http.Error(w, "no hint", http.StatusBadRequest)
		}
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
		name := r.Form.Get("username")
		seeded := strings.HasPrefix(name, "bench-") && strings.HasSuffix(name, "@"+benchDomain)
		if (name != "alice" && !seeded) || r.Form.Get("password") != "pw" {
			http.Error(w, "wrong", http.StatusUnauthorized)
			return
		}
		signedIn.Store(name, true)
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
			_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt0","id_token":"it"}`))
		case "urn:ietf:params:oauth:grant-type:device_code":
			http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
		case "refresh_token":
			n := refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "refresh_token": "rt" + string(rune('0'+n%10))})
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			if r.Form.Get("subject_token") != "at" ||
				r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
				http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"exchanged"}`))
		}
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"d1","user_code":"U1"}`))
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
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("token") != "at" {
			http.Error(w, "no", http.StatusBadRequest)
		}
	})
	// A push is created, as the engine answers it: a driver that took only a 200
	// counted every one of these as a failure.
	mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:r1","expires_in":300}`))
	})
	mux.HandleFunc("GET /admin/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sgnadm" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"users":[]}`))
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

// What an operation needs and did not come to measure stays out of its latency: a
// sign-out timed with its sign-in would report the password hash.
func TestSetupIsKeptOutOfTheLatency(t *testing.T) {
	op := func(ctx context.Context) error {
		if err := outside(ctx, func() error {
			time.Sleep(40 * time.Millisecond)
			return nil
		}); err != nil {
			return err
		}
		time.Sleep(time.Millisecond)
		return nil
	}
	got := run(context.Background(), []func(context.Context) error{op}, 200*time.Millisecond)
	if len(got.lat) == 0 {
		t.Fatal("nothing was measured")
	}
	for _, d := range got.lat {
		if d >= 30*time.Millisecond {
			t.Errorf("an operation of a millisecond measured %s with its setup in it", d)
		}
	}
}

// A provider that serves introspection apart from discovery, to a client other than
// the one that holds the token, is measured there and as that client; with nowhere to
// introspect, the scenario says so rather than posting to an empty URL.
func TestIntrospectionCanBeAskedElsewhereAsAnotherClient(t *testing.T) {
	srv := fakeProvider(t)
	var asked atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		// Form-encoded inside Basic, as RFC 6749 §2.3.1 has it and the driver sends it.
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if !ok || id != "api" || secret != "api+secret" || r.URL.Path != "/admin/introspect" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		asked.Add(1)
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	t.Cleanup(api.Close)
	c := &config{Issuer: srv.URL, ClientID: "bench", ClientSecret: "s+1", Concurrency: 1,
		Duration: 100 * time.Millisecond, IntrospectURL: api.URL + "/admin/introspect",
		IntrospectClientID: "api", IntrospectClientSecret: "api+secret"}
	res, err := measure(context.Background(), c, "introspect", scenarios["introspect"])
	if err != nil || res.Ops == 0 || res.Errors != 0 || asked.Load() == 0 {
		t.Fatalf("introspection elsewhere measured %+v, %v, %d asked there", res, err, asked.Load())
	}

	// The token's own client is refused there, and that is an error, not a measurement.
	c.IntrospectClientID, c.IntrospectClientSecret = "", ""
	if res, err := measure(context.Background(), c, "introspect", scenarios["introspect"]); err == nil && res.Errors == 0 {
		t.Errorf("introspecting as the wrong client measured %+v", res)
	}

	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": srv.URL + "/token"})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(bare.Close)
	none := &config{Issuer: bare.URL, ClientID: "bench", ClientSecret: "s+1", Concurrency: 1, Duration: 50 * time.Millisecond}
	if res, err := measure(context.Background(), none, "introspect", scenarios["introspect"]); err == nil &&
		!strings.Contains(res.FirstError, "-introspect-url") {
		t.Errorf("a provider with no introspection endpoint measured %+v", res)
	}
}

// signedIn is every name the fake provider's login form accepted.
var signedIn sync.Map

// With -signin-people the sign-in scenario is many people, not -username over and
// over: each turn the next seeded person, in a browser of their own.
func TestSignInTakesTurnsThroughSeededPeople(t *testing.T) {
	srv := fakeProvider(t)
	signedIn.Clear()
	c := &config{Issuer: srv.URL, ClientID: "bench", ClientSecret: "s+1",
		RedirectURI: "https://bench.invalid/cb", Scope: "openid offline_access",
		Username: "alice", Password: "pw", Concurrency: 2, Duration: 150 * time.Millisecond, SignInPeople: 3}
	res, err := measure(context.Background(), c, "signin", scenarios["signin"])
	if err != nil || res.Ops < 3 || res.Errors != 0 {
		t.Fatalf("signin with -signin-people measured %+v, %v", res, err)
	}
	got := map[string]bool{}
	signedIn.Range(func(k, _ any) bool { got[k.(string)] = true; return true })
	want := map[string]bool{"bench-1@" + benchDomain: true, "bench-2@" + benchDomain: true, "bench-3@" + benchDomain: true}
	if len(got) != len(want) {
		t.Fatalf("signed in %v, want exactly %v", got, want)
	}
	for name := range got {
		if !want[name] {
			t.Errorf("signed in %s, which is not one of the three seeded people (-username is alice)", name)
		}
	}

	// A worker of a scenario that signs in once to begin, refresh here, is one of them
	// too: two workers, two seeded people, and never -username.
	signedIn.Clear()
	if res, err := measure(context.Background(), c, "refresh", scenarios["refresh"]); err != nil || res.Errors != 0 {
		t.Fatalf("refresh with -signin-people measured %+v, %v", res, err)
	}
	got = map[string]bool{}
	signedIn.Range(func(k, _ any) bool { got[k.(string)] = true; return true })
	if len(got) != 2 || got["alice"] {
		t.Errorf("refresh's two workers signed in as %v, want two of the seeded people", got)
	}
	for name := range got {
		if !want[name] {
			t.Errorf("a refresh worker signed in as %s", name)
		}
	}
}

// Every HTTP scenario runs against the fake for a moment, with no errors, and
// reports what it measured.
func TestTheHTTPScenariosMeasureAProvider(t *testing.T) {
	srv := fakeProvider(t)
	c := &config{Issuer: srv.URL, ClientID: "bench", ClientSecret: "s+1",
		RedirectURI: "https://bench.invalid/cb", Scope: "openid offline_access",
		Username: "alice", Password: "pw", Concurrency: 2, Duration: 150 * time.Millisecond,
		AdminURL: srv.URL, AdminToken: "sgnadm", People: 3}
	for _, name := range []string{"discovery", "jwks", "client-credentials", "introspect", "signin", "refresh", "userinfo",
		"revoke", "par", "admin-list", "device-start", "token-exchange", "device-poll", "ciba-start", "end-session"} {
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
