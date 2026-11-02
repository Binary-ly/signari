// Package cimd reads Client ID Metadata Documents, draft-ietf-oauth-client-id-metadata-document
// (specs/client-id-metadata-document.txt): a client whose client_id is an https URL, and
// whose registration is the document at that URL. What is fetched is an anonymous
// stranger's statement about itself, so everything here is about what not to believe.
package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// MaxDocumentBytes is §8.7: "The recommended maximum size to read is 5 kilobytes."
	MaxDocumentBytes = 5 << 10
	// maxKeySetBytes is a jwks_uri's limit, a few keys and their certificates.
	maxKeySetBytes = 64 << 10
	// FetchTimeout bounds what a stranger's slow server can do to an authorization
	// request that is waiting on it.
	FetchTimeout = 5 * time.Second

	// §5.2 lets the bounds on a cache lifetime be this server's own. Short enough at the
	// top that a client's new redirect URL, or a client gone bad, takes a day at worst,
	// and long enough at the bottom that a sign-in does not tell its operator of itself
	// each time (§9.1).
	minLifetime     = time.Minute
	defaultLifetime = time.Hour
	maxLifetime     = 24 * time.Hour
)

// Authentication methods a document can name. §4.1 rules out anything with a shared
// secret, since there is no way to have established one.
const (
	AuthNone          = "none"
	AuthPrivateKeyJWT = "private_key_jwt"
)

// Document is what a client says of itself, as far as anything here reads it.
type Document struct {
	ClientID     string          `json:"client_id"`
	Name         string          `json:"client_name"`
	RedirectURIs []string        `json:"redirect_uris"`
	GrantTypes   []string        `json:"grant_types"`
	Responses    []string        `json:"response_types"`
	AuthMethod   string          `json:"token_endpoint_auth_method"`
	Scope        string          `json:"scope"`
	JWKS         json.RawMessage `json:"jwks"`
	JWKSURI      string          `json:"jwks_uri"`

	// Parsed so that their presence can be refused (§4.1).
	ClientSecret          json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt json.RawMessage `json:"client_secret_expires_at"`
}

// CheckURL holds a client_id to §3's rules for a Client Identifier URL.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	switch {
	case u.Scheme != "https":
		return errors.New("a Client Identifier URL MUST use the https URL scheme")
	case u.Host == "":
		return errors.New("a Client Identifier URL has a host")
	case u.User != nil:
		return errors.New("a Client Identifier URL MUST NOT contain a userinfo component")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("a Client Identifier URL MUST NOT contain a fragment component")
	case u.Path == "":
		return errors.New("a Client Identifier URL MUST contain a path component")
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if unescaped, err := url.PathUnescape(segment); err != nil || unescaped == "." || unescaped == ".." {
			return errors.New("a Client Identifier URL MUST NOT contain single-dot or double-dot path components")
		}
	}
	return nil
}

// Fetch reads the document at a Client Identifier URL, and says how long it may be kept.
// Anything short of a sound document is an error, which §5.2 forbids keeping.
func Fetch(ctx context.Context, client *http.Client, clientID string) (*Document, time.Duration, error) {
	if err := CheckURL(clientID); err != nil {
		return nil, 0, err
	}
	body, header, err := get(ctx, client, clientID, MaxDocumentBytes)
	if err != nil {
		return nil, 0, err
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("the document is not JSON: %w", err)
	}
	if err := doc.check(clientID); err != nil {
		return nil, 0, err
	}
	return &doc, lifetime(header), nil
}

func (d *Document) check(clientID string) error {
	// §4: "MUST match the URL that the authorization server used to fetch the document",
	// by simple string comparison, so that one site cannot speak for another.
	if d.ClientID != clientID {
		return fmt.Errorf("the document says it is %q", d.ClientID)
	}
	if len(d.ClientSecret) > 0 || len(d.ClientSecretExpiresAt) > 0 {
		return errors.New("a document MUST NOT use client_secret or client_secret_expires_at")
	}
	if d.AuthMethod == "" {
		d.AuthMethod = AuthNone
	}
	if d.AuthMethod != AuthNone && d.AuthMethod != AuthPrivateKeyJWT {
		return fmt.Errorf("token_endpoint_auth_method %q is not one this server takes from a document", d.AuthMethod)
	}
	if d.AuthMethod == AuthPrivateKeyJWT && len(d.JWKS) == 0 && d.JWKSURI == "" {
		return errors.New("private_key_jwt with no key to check it by")
	}
	if len(d.RedirectURIs) == 0 {
		return errors.New("no redirect_uris")
	}
	for _, uri := range d.RedirectURIs {
		if err := checkRedirect(clientID, uri); err != nil {
			return err
		}
	}
	if len(d.GrantTypes) == 0 {
		d.GrantTypes = []string{"authorization_code"}
	}
	for _, grant := range d.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			return fmt.Errorf("grant type %q is not one this server gives a client on its own word", grant)
		}
	}
	if !slices.Contains(d.GrantTypes, "authorization_code") {
		return errors.New("no authorization_code among the grant types")
	}
	for _, response := range d.Responses {
		if response != "code" {
			return fmt.Errorf("response type %q is not one this server takes", response)
		}
	}
	return nil
}

// checkRedirect is §8.1's "restrict the redirect_uri to the same-origin as the Client ID
// Metadata Document", which is what stops a document at evil.example naming a redirect at
// somebody else's application and riding on its name. The exception is the loopback
// address a native application listens on, which reaches nobody but the person's machine.
func checkRedirect(clientID, uri string) error {
	id, err := url.Parse(clientID)
	if err != nil {
		return err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("redirect_uri %q: %w", uri, err)
	}
	if u.Scheme == id.Scheme && u.Host == id.Host {
		return nil
	}
	if host := u.Hostname(); u.Scheme == "http" && (host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return fmt.Errorf("redirect_uri %q is neither at the document's own origin nor on loopback", uri)
}

// Keys answers the key set a private_key_jwt client named, fetched if it named it by URL,
// and refuses anything private in it (§4.1).
func (d *Document) Keys(ctx context.Context, client *http.Client) (json.RawMessage, error) {
	raw := d.JWKS
	if len(raw) == 0 && d.JWKSURI != "" {
		// §8.6 has this URL held to the same rules, and the scheme to ones this server knows.
		u, err := url.Parse(d.JWKSURI)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("jwks_uri %q is not an https URL", d.JWKSURI)
		}
		if raw, _, err = get(ctx, client, d.JWKSURI, maxKeySetBytes); err != nil {
			return nil, fmt.Errorf("fetching jwks_uri: %w", err)
		}
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("the key set did not parse: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the key set holds no keys")
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || !k.Valid() {
			return nil, errors.New("the key set holds something other than a usable public key")
		}
	}
	return raw, nil
}

// get is a GET that follows nothing and reads no further than limit.
func get(ctx context.Context, client *http.Client, target string, limit int64) ([]byte, http.Header, error) {
	// §5: "The authorization server MUST NOT automatically follow HTTP redirects".
	once := *client
	once.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := once.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("it answered %d, and only a 200 will do", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && !(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"))) {
		return nil, nil, fmt.Errorf("it answered in %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	// §8.7: "treating the response as an error if that limit is reached".
	if int64(len(body)) > limit {
		return nil, nil, fmt.Errorf("it is over %d bytes", limit)
	}
	return body, resp.Header, nil
}

// lifetime is how long to keep a document, §5.2: the cache headers, between our bounds.
func lifetime(header http.Header) time.Duration {
	found := defaultLifetime
	for _, directive := range strings.Split(header.Get("Cache-Control"), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		switch name {
		case "no-store", "no-cache":
			return minLifetime
		case "max-age":
			if seconds, err := strconv.Atoi(strings.Trim(value, `"`)); err == nil {
				found = time.Duration(seconds) * time.Second
			}
		}
	}
	return min(max(found, minLifetime), maxLifetime)
}
