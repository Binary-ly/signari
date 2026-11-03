package keys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"signari.dev/engine/internal/safedial"
)

// Vault's transit secrets engine, or OpenBao's, which answers the same API (3.14).
//
// Transit makes a key it will not hand out unless asked to when the key is made,
// and signs with it on request. Each key here is made not exportable and with no
// plaintext backup, named by its kid, and signed with at version 1 only: the
// version made and published. A version added inside Vault later is a key no
// relying party was given, so it is never used. Rotation is this deployment's,
// to a new kid.
//
// No transit specification is in specs/, so what this relies on was measured
// against OpenBao 2.4.1: a create of a name already held answers 200 and keeps
// the key it had, so Generate asks first; a missing key is 404; an Ed25519 key's
// public half is raw base64 where the others are PEM, and it signs the message
// itself; ECDSA signatures come back DER with marshaling_algorithm asn1; RSA-PSS
// takes salt_length "hash"; every signature is prefixed "vault:v<version>:"; and
// a key name may not begin or end with a hyphen, which a kid may, so the name is
// transitName's.
type vaultBackend struct {
	base   string // <addr>/v1/<mount>
	token  func() (string, error)
	client *http.Client
}

func newVault(addr, mount string, token func() (string, error)) (Backend, error) {
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("SIGNARI_VAULT_ADDR %q is not an http or https address", addr)
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("SIGNARI_VAULT_ADDR is plain http to %s, which would send the token "+
			"across the network in clear; use https, or a loopback address", u.Host)
	}
	if mount = strings.Trim(mount, "/"); mount == "" {
		mount = "transit"
	}
	return &vaultBackend{
		base:  strings.TrimRight(u.String(), "/") + "/v1/" + mount,
		token: token,
		// Not a safedial client: the server is the operator's own, named only by
		// SIGNARI_VAULT_ADDR, and usually on the network safedial exists to keep
		// relying parties out of. Its trust store is the one every other client
		// here uses, so SIGNARI_CA_BUNDLE reaches it.
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: safedial.Roots(), MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 5 * time.Second,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 4,
				ForceAttemptHTTP2:   true,
			},
			// A redirect would carry the token somewhere nobody named.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (b *vaultBackend) Scheme() string { return "vault-transit" }

// transitName is the transit key a kid is kept as: one that begins and ends
// with a letter whatever the kid does, and says whose it is to anyone listing
// the mount.
func transitName(kid string) string { return "signari-" + kid + "-key" }

// How long a call may take. Making an RSA key took longer than ten seconds
// under load; a signature that takes that long has a request waiting on it.
const (
	vaultCallTimeout     = 10 * time.Second
	vaultGenerateTimeout = time.Minute
)

// call sends one request and decodes the answer's body into out. It returns
// the status with any error, so a caller can tell a missing key from a failure.
func (b *vaultBackend) call(method, path string, body, out any) (int, error) {
	return b.callWithin(vaultCallTimeout, method, path, body, out)
}

func (b *vaultBackend) callWithin(limit time.Duration, method, path string, body, out any) (int, error) {
	token, err := b.token()
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode/100 != 2 {
		var refusal struct {
			Errors []string `json:"errors"`
		}
		detail := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &refusal) == nil && len(refusal.Errors) > 0 {
			detail = strings.Join(refusal.Errors, "; ")
		}
		return resp.StatusCode, fmt.Errorf("%s %s answered %d: %s", method, path, resp.StatusCode, detail)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func vaultKeyType(alg Algorithm, rsaBits int) (string, error) {
	switch {
	case isRSA(alg):
		return fmt.Sprintf("rsa-%d", rsaBits), nil
	case alg == ES256:
		return "ecdsa-p256", nil
	case alg == ES384:
		return "ecdsa-p384", nil
	case alg == ES512:
		return "ecdsa-p521", nil
	case alg == EdDSA:
		return "ed25519", nil
	}
	return "", fmt.Errorf("%s keys are not made in the transit engine here", alg)
}

func (b *vaultBackend) Generate(name string, alg Algorithm, rsaBits int) (crypto.Signer, error) {
	typ, err := vaultKeyType(alg, rsaBits)
	if err != nil {
		return nil, err
	}
	path := "/keys/" + url.PathEscape(transitName(name))
	switch status, err := b.call(http.MethodGet, path, nil, nil); {
	case status == http.StatusOK:
		return nil, fmt.Errorf("the transit engine already holds a key %q", name)
	case status != http.StatusNotFound:
		return nil, err
	}
	if _, err := b.callWithin(vaultGenerateTimeout, http.MethodPost, path,
		map[string]any{"type": typ, "exportable": false, "allow_plaintext_backup": false}, nil); err != nil {
		return nil, err
	}
	return b.Open(name)
}

func (b *vaultBackend) Open(name string) (crypto.Signer, error) {
	var key struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	name = transitName(name)
	if _, err := b.call(http.MethodGet, "/keys/"+url.PathEscape(name), nil, &key); err != nil {
		return nil, err
	}
	first, ok := key.Data.Keys["1"]
	if !ok {
		return nil, fmt.Errorf("the transit engine no longer holds version 1 of %q, the one published", name)
	}
	var public crypto.PublicKey
	if key.Data.Type == "ed25519" {
		raw, err := base64.StdEncoding.DecodeString(first.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("the public half of %q is not an Ed25519 key", name)
		}
		public = ed25519.PublicKey(raw)
	} else {
		block, _ := pem.Decode([]byte(first.PublicKey))
		if block == nil {
			return nil, fmt.Errorf("the public half of %q is not PEM", name)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the public half of %q: %w", name, err)
		}
		public = parsed
	}
	return &vaultSigner{backend: b, name: name, public: public}, nil
}

// vaultSigner signs with version 1 of one transit key.
type vaultSigner struct {
	backend *vaultBackend
	name    string
	public  crypto.PublicKey
}

func (s *vaultSigner) Public() crypto.PublicKey { return s.public }

var vaultHashes = map[crypto.Hash]string{
	crypto.SHA256: "sha2-256",
	crypto.SHA384: "sha2-384",
	crypto.SHA512: "sha2-512",
}

func (s *vaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	path := "/sign/" + url.PathEscape(s.name)
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(digest), "key_version": 1}
	if _, ok := s.public.(ed25519.PublicKey); ok {
		if opts.HashFunc() != crypto.Hash(0) {
			return nil, fmt.Errorf("an Ed25519 key signs the message itself, not a %s digest", opts.HashFunc())
		}
	} else {
		hash, ok := vaultHashes[opts.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("the transit engine is not asked to sign a %s digest here", opts.HashFunc())
		}
		path += "/" + hash
		body["prehashed"] = true
		body["marshaling_algorithm"] = "asn1"
		if _, ok := s.public.(*rsa.PublicKey); ok {
			body["signature_algorithm"] = "pkcs1v15"
			if pss, ok := opts.(*rsa.PSSOptions); ok {
				body["signature_algorithm"] = "pss"
				switch {
				case pss.SaltLength == rsa.PSSSaltLengthEqualsHash:
					body["salt_length"] = "hash"
				case pss.SaltLength > 0:
					body["salt_length"] = pss.SaltLength
				default:
					return nil, fmt.Errorf("an RSA-PSS salt length of %d is not asked of the transit engine", pss.SaltLength)
				}
			}
		}
	}
	var signed struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if _, err := s.backend.call(http.MethodPost, path, body, &signed); err != nil {
		return nil, err
	}
	encoded, ok := strings.CutPrefix(signed.Data.Signature, "vault:v1:")
	if !ok {
		return nil, fmt.Errorf("the transit engine signed %q with a version other than the one published", s.name)
	}
	return base64.StdEncoding.DecodeString(encoded)
}
