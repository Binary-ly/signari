// Command go-quickstart is an application that signs people in with Signari,
// using nothing outside Go's standard library: the authorization code flow
// with PKCE, and the ID token's signature, issuer, audience, expiry and nonce
// checked here. See docs/quickstart-go.md.
//
//	SIGNARI_ISSUER=https://id.example.com CLIENT_ID=quickstart CLIENT_SECRET=... \
//	REDIRECT_URI=http://127.0.0.1:8080/callback go run .
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// provider is what the discovery document says.
type provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// pending is one sign-in between the redirect out and the callback.
type pending struct {
	verifier, nonce string
	made            time.Time
}

type app struct {
	p                          provider
	clientID, secret, redirect string
	mu                         sync.Mutex
	pending                    map[string]pending // by state
}

func main() {
	issuer, clientID := os.Getenv("SIGNARI_ISSUER"), os.Getenv("CLIENT_ID")
	redirect := os.Getenv("REDIRECT_URI")
	if issuer == "" || clientID == "" || redirect == "" {
		log.Fatal("set SIGNARI_ISSUER, CLIENT_ID and REDIRECT_URI, and CLIENT_SECRET for a confidential client")
	}
	a := &app{clientID: clientID, secret: os.Getenv("CLIENT_SECRET"), redirect: redirect,
		pending: map[string]pending{}}
	// Discovery, and the issuer it names must be the one configured: an
	// application that took another would accept tokens minted for it.
	if err := getJSON(strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &a.p); err != nil {
		log.Fatal(err)
	}
	if a.p.Issuer != issuer {
		log.Fatalf("the discovery document names the issuer %q, not %q", a.p.Issuer, issuer)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/login", a.login)
	http.HandleFunc(u.Path, a.callback)
	log.Printf("open http://%s/login", u.Host)
	log.Fatal(http.ListenAndServe(u.Host, nil))
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// login sends the browser to Signari with a fresh state, nonce and PKCE
// verifier, kept here until the callback.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	state, nonce, verifier := random(), random(), random()
	a.mu.Lock()
	a.pending[state] = pending{verifier: verifier, nonce: nonce, made: time.Now()}
	a.mu.Unlock()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {a.redirect},
		"scope": {"openid profile email"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, a.p.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

// callback exchanges the code and checks the ID token before believing it.
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "the sign-in was refused: "+e+": "+q.Get("error_description"), http.StatusForbidden)
		return
	}
	a.mu.Lock()
	p, ok := a.pending[q.Get("state")]
	delete(a.pending, q.Get("state"))
	a.mu.Unlock()
	if !ok || time.Since(p.made) > 10*time.Minute {
		http.Error(w, "unknown or stale state", http.StatusBadRequest)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"redirect_uri": {a.redirect}, "code_verifier": {p.verifier}}
	if a.secret == "" {
		// A public client names itself, and PKCE is its proof.
		form.Set("client_id", a.clientID)
	}
	req, _ := http.NewRequest(http.MethodPost, a.p.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.secret != "" {
		// client_secret_basic, each half form-encoded first, as the server
		// decodes them (engine/internal/oauth/token.go, parseBasic): a
		// secret holding a '+' is otherwise read as a space.
		req.SetBasicAuth(url.QueryEscape(a.clientID), url.QueryEscape(a.secret))
	}
	var tokens struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := doJSON(req, &tokens); err != nil || tokens.IDToken == "" {
		http.Error(w, fmt.Sprintf("the token request failed: %v %s %s", err, tokens.Error, tokens.Desc),
			http.StatusBadGateway)
		return
	}
	claims, err := a.verify(tokens.IDToken, p.nonce)
	if err != nil {
		http.Error(w, "the ID token was refused: "+err.Error(), http.StatusForbidden)
		return
	}
	who, _ := claims["email"].(string)
	if who == "" {
		who, _ = claims["sub"].(string)
	}
	fmt.Fprintf(w, "<p>Signed in as %s.</p>", html.EscapeString(who))
}

// verify checks the ID token's signature against the published keys, then
// its issuer, audience, expiry and nonce.
func (a *app) verify(token, nonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var header struct{ Alg, Kid string }
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	var jwks struct {
		Keys []struct{ Kty, Kid, Crv, X, Y, N, E string }
	}
	if err := getJSON(a.p.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	verified := false
	for _, k := range jwks.Keys {
		if k.Kid != header.Kid {
			continue
		}
		switch {
		case header.Alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256" && len(sig) == 64:
			x, y := bigOf(k.X), bigOf(k.Y)
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
			verified = ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		case header.Alg == "RS256" && k.Kty == "RSA":
			pub := &rsa.PublicKey{N: bigOf(k.N), E: int(bigOf(k.E).Int64())}
			verified = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
		}
	}
	if !verified {
		return nil, fmt.Errorf("no published key verifies it (alg %s, kid %s)", header.Alg, header.Kid)
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, err
	}
	if claims["iss"] != a.p.Issuer {
		return nil, fmt.Errorf("issued by %v", claims["iss"])
	}
	if !audienceHas(claims["aud"], a.clientID) {
		return nil, errors.New("not issued to this application")
	}
	if exp, _ := claims["exp"].(float64); time.Now().After(time.Unix(int64(exp), 0)) {
		return nil, errors.New("expired")
	}
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("the nonce is not this sign-in's")
	}
	return claims, nil
}

func audienceHas(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, x := range v {
			if x == clientID {
				return true
			}
		}
	}
	return false
}

func bigOf(s string) *big.Int {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return new(big.Int).SetBytes(b)
}

func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func getJSON(target string, v any) error {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	return doJSON(req, v)
}

func doJSON(req *http.Request, v any) error {
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("%s answered %d: %w", req.URL, resp.StatusCode, err)
	}
	return nil
}
