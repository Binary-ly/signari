package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) *ca {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: c, key: k}
}

// issue returns a leaf certificate signed by this CA, and its private key.
func (a *ca) issue(t *testing.T, name string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &k.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func chainHeader(certs ...*x509.Certificate) []any {
	out := make([]any, 0, len(certs))
	for _, c := range certs {
		// RFC 7515 §4.1.6: base64, NOT base64url.
		out = append(out, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return out
}

func TestAnX5CChainIsAcceptedOnlyWhenItReachesAConfiguredRoot(t *testing.T) {
	root := newCA(t, "trusted-root")
	other := newCA(t, "somebody-elses-root")
	now := time.Now()

	leaf, _ := root.issue(t, "wallet", now.Add(time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	chain, err := ParseX5CChain(chainHeader(leaf))
	if err != nil {
		t.Fatalf("parsing a well-formed chain: %v", err)
	}
	key, err := ResolveX5CKey(chain, pool, string(jose.ES256), now)
	if err != nil {
		t.Fatalf("a chain to the configured root was refused: %v", err)
	}
	if key.Key == nil {
		t.Fatal("no key returned, so nothing could be bound")
	}

	t.Run("no roots configured means refused, not trusted", func(t *testing.T) {
		if _, err := ResolveX5CKey(chain, nil, string(jose.ES256), now); err == nil {
			t.Fatal("a chain was accepted with no trusted roots configured. That is " +
				"another implementation's behaviour and it makes x5c no stronger than an inline jwk: " +
				"a wallet mints its own certificate and the key is treated as established")
		} else if !strings.Contains(err.Error(), "no trusted x5c roots") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("a chain to a different root is refused", func(t *testing.T) {
		theirLeaf, _ := other.issue(t, "wallet", now.Add(time.Hour))
		c, err := ParseX5CChain(chainHeader(theirLeaf))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveX5CKey(c, pool, string(jose.ES256), now); err == nil {
			t.Fatal("a chain signed by an untrusted CA was accepted")
		}
	})

	t.Run("a self-signed leaf is refused", func(t *testing.T) {
		selfSigned := newCA(t, "i-signed-myself")
		c, err := ParseX5CChain(chainHeader(selfSigned.cert))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveX5CKey(c, pool, string(jose.ES256), now); err == nil {
			t.Fatal("a self-signed certificate was accepted as a proof key")
		}
	})

	t.Run("an expired leaf is refused", func(t *testing.T) {
		expired, _ := root.issue(t, "wallet", now.Add(-time.Minute))
		c, err := ParseX5CChain(chainHeader(expired))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveX5CKey(c, pool, string(jose.ES256), now); err == nil {
			t.Fatal("an expired certificate was accepted")
		}
	})

	// RFC 7515 §4.1.6 uses base64, not base64url. Every other JOSE value is
	// base64url, so this is the encoding people get wrong.
	t.Run("base64url is not base64", func(t *testing.T) {
		bad := []any{base64.RawURLEncoding.EncodeToString(leaf.Raw)}
		if _, err := ParseX5CChain(bad); err == nil {
			// RawURL happens to decode as valid base64 only when there is no
			// padding difference; assert the parse either fails or yields a
			// chain that does not verify.
			c, _ := ParseX5CChain(bad)
			if _, verr := ResolveX5CKey(c, pool, string(jose.ES256), now); verr == nil {
				t.Error("a base64url-encoded certificate was accepted")
			}
		}
	})

	t.Run("an over-long chain is refused before parsing", func(t *testing.T) {
		var long []any
		for i := 0; i <= MaxX5CChainLength; i++ {
			long = append(long, base64.StdEncoding.EncodeToString(leaf.Raw))
		}
		if _, err := ParseX5CChain(long); err == nil {
			t.Errorf("a chain of %d was accepted, over the limit of %d",
				len(long), MaxX5CChainLength)
		}
	})
}
