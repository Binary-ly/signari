package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// upstream is what a scenario needs on the far side of the engine: an OpenID provider
// to sign in through and a SCIM server to provision into. What it says is signed or
// stored as a real one's would be, so the engine does its real work against it, and
// what it costs is a signature and a map, small beside what is being measured.
type upstream struct {
	issuer string
	key    *ecdsa.PrivateKey
	people int

	next                      atomic.Int64
	tokens, created, replaced atomic.Int64

	mu    sync.Mutex
	users map[string]map[string]any
	order []string
}

func upstreamCommand(args []string) error {
	fs := flag.NewFlagSet("upstream", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:18991", "host:port to listen on")
	cert := fs.String("tls-cert", "", "certificate, which the engine must trust (SIGNARI_CA_BUNDLE)")
	key := fs.String("tls-key", "", "its key, a PKCS#8 P-256 key, which also signs ID tokens and assertions")
	people := fs.Int("people", 1000, "how many upstream subjects to sign in by turns")
	ldapAddr := fs.String("ldap-addr", "", "host:port to serve a directory on, over TLS (ldaps)")
	directory := fs.Int("directory", 100000, "how many people that directory holds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cert == "" || *key == "" {
		return fmt.Errorf("give -tls-cert and -tls-key: the engine fetches keys and tokens over https only")
	}
	signer, err := readSigningKey(*key)
	if err != nil {
		return err
	}
	if *ldapAddr != "" {
		pair, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return err
		}
		l, err := tls.Listen("tcp", *ldapAddr, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		go func() { _ = serveDirectory(l, *directory) }()
	}
	u := newUpstream("https://"+*addr, signer, *people)
	srv := &http.Server{Addr: *addr, Handler: u.routes(), ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServeTLS(*cert, *key)
}

func newUpstream(issuer string, key *ecdsa.PrivateKey, people int) *upstream {
	return &upstream{issuer: strings.TrimRight(issuer, "/"), key: key, people: people,
		users: map[string]map[string]any{}}
}

func (u *upstream) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeUpstreamJSON(w, http.StatusOK, map[string]any{
			"issuer": u.issuer, "authorization_endpoint": u.issuer + "/authorize", "token_endpoint": u.issuer + "/token",
			"jwks_uri": u.issuer + "/jwks", "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		x, y := make([]byte, 32), make([]byte, 32)
		u.key.X.FillBytes(x)
		u.key.Y.FillBytes(y)
		writeUpstreamJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": signingKID, "x": b64(x), "y": b64(y)}}})
	})
	mux.HandleFunc("GET /authorize", u.authorize)
	mux.HandleFunc("POST /token", u.token)
	mux.HandleFunc("GET /scim/v2/Users", u.listUsers)
	mux.HandleFunc("POST /scim/v2/Users", u.createUser)
	mux.HandleFunc("GET /scim/v2/Users/{id}", u.getUser)
	mux.HandleFunc("PUT /scim/v2/Users/{id}", u.replaceUser)
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", u.replaceUser)
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		writeUpstreamJSON(w, http.StatusOK, map[string]int64{"tokens": u.tokens.Load(),
			"created": u.created.Load(), "replaced": u.replaced.Load()})
	})
	return mux
}

// authorize signs in whoever comes next, at once: the person's minutes at somebody
// else's password page are no part of what the engine does.
func (u *upstream) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || back.Scheme == "" {
		http.Error(w, "no redirect_uri", http.StatusBadRequest)
		return
	}
	n := int(u.next.Add(1))%u.people + 1
	v := back.Query()
	v.Set("code", strconv.Itoa(n)+"."+q.Get("nonce"))
	v.Set("state", q.Get("state"))
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (u *upstream) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "no form", http.StatusBadRequest)
		return
	}
	person, nonce, ok := strings.Cut(r.Form.Get("code"), ".")
	if !ok {
		writeUpstreamJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	audience := r.Form.Get("client_id")
	if id, _, basic := r.BasicAuth(); basic {
		audience, _ = url.QueryUnescape(id)
	}
	now := time.Now()
	idToken, err := signES256(u.key, map[string]any{
		"iss": u.issuer, "sub": "upstream-" + person, "aud": audience, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
		"email": "upstream-" + person + "@" + benchDomain, "email_verified": true,
	})
	if err != nil {
		http.Error(w, "signing", http.StatusInternalServerError)
		return
	}
	u.tokens.Add(1)
	writeUpstreamJSON(w, http.StatusOK, map[string]any{"access_token": randomString(16), "token_type": "Bearer",
		"expires_in": 300, "id_token": idToken})
}

var userNameFilter = regexp.MustCompile(`(?i)^userName eq "([^"]*)"$`)

// listUsers pages what has been stored, in the order it came, with the one filter a
// SCIM client asks: RFC 7644 §3.4.2.2's `userName eq`.
func (u *upstream) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	start, _ := strconv.Atoi(q.Get("startIndex"))
	count, _ := strconv.Atoi(q.Get("count"))
	start, count = max(start, 1), max(count, 100)
	u.mu.Lock()
	defer u.mu.Unlock()
	page := []map[string]any{}
	total := len(u.order)
	if m := userNameFilter.FindStringSubmatch(q.Get("filter")); m != nil {
		total = 0
		for _, id := range u.order {
			if u.users[id]["userName"] == m[1] {
				page, total = append(page, u.users[id]), 1
				break
			}
		}
	} else {
		for i := start - 1; i >= 0 && i < total && len(page) < count; i++ {
			page = append(page, u.users[u.order[i]])
		}
	}
	writeUpstreamJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": total, "startIndex": start, "itemsPerPage": len(page), "Resources": page,
	})
}

func (u *upstream) createUser(w http.ResponseWriter, r *http.Request) {
	var user map[string]any
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "not JSON", http.StatusBadRequest)
		return
	}
	id := randomString(12)
	user["id"] = id
	u.mu.Lock()
	u.users[id] = user
	u.order = append(u.order, id)
	u.mu.Unlock()
	u.created.Add(1)
	writeUpstreamJSON(w, http.StatusCreated, user)
}

func (u *upstream) getUser(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	user, ok := u.users[r.PathValue("id")]
	u.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeUpstreamJSON(w, http.StatusOK, user)
}

func (u *upstream) replaceUser(w http.ResponseWriter, r *http.Request) {
	var user map[string]any
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "not JSON", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	user["id"] = id
	u.mu.Lock()
	_, ok := u.users[id]
	if ok {
		u.users[id] = user
	}
	u.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	u.replaced.Add(1)
	writeUpstreamJSON(w, http.StatusOK, user)
}

func writeUpstreamJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// signingKID names the one key upstream and the assertions sign with.
const signingKID = "bench"

func readSigningKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not a P-256 key", path)
	}
	return key, nil
}

// signES256 is a compact JWS (RFC 7515) over claims.
func signES256(key *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	head, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": signingKID})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
