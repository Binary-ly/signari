//go:build pkcs11 && cgo

package keys

import (
	"crypto"
	"fmt"
	"sync"

	"github.com/eclipse-keypont/crypto11"
)

// A PKCS#11 module (3.14). Built only with `-tags pkcs11` and cgo, because a
// module is a C library loaded at run time, and the static image this project
// ships has no C at all; the pkcs11 image target in the Dockerfile is the one
// that does.
//
// A key is made in the token with the token as its home (CKA_TOKEN), sensitive
// and not extractable, so the module will not hand its private half to anyone,
// this process included. Its CKA_ID and CKA_LABEL are both the kid, which is how
// it is found again and what an operator sees with the module's own tools.

type pkcs11Backend struct {
	config crypto11.Config
	mu     sync.Mutex
	ctx    *crypto11.Context
}

func newPKCS11(module, token, pin string) (Backend, error) {
	return &pkcs11Backend{config: crypto11.Config{Path: module, TokenLabel: token, Pin: pin}}, nil
}

func (b *pkcs11Backend) Scheme() string { return "pkcs11" }

// context logs in on first use rather than when the keyring is loaded: every
// command loads the keyring, and one that signs nothing should not need the
// token present. serve loads its keys before it listens, so a module it cannot
// reach still stops it at startup. A failure is not kept, so the next key
// refresh tries again.
func (b *pkcs11Backend) context() (*crypto11.Context, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx != nil {
		return b.ctx, nil
	}
	c, err := crypto11.Configure(&b.config)
	if err != nil {
		return nil, fmt.Errorf("opening token %q with %s: %w", b.config.TokenLabel, b.config.Path, err)
	}
	b.ctx = c
	return c, nil
}

func (b *pkcs11Backend) Generate(name string, alg Algorithm, rsaBits int) (crypto.Signer, error) {
	c, err := b.context()
	if err != nil {
		return nil, err
	}
	id := []byte(name)
	if existing, err := c.FindKeyPairs(id, nil); err != nil {
		return nil, err
	} else if len(existing) > 0 {
		return nil, fmt.Errorf("the token already holds a key %q", name)
	}
	public, err := crypto11.NewAttributeSetWithIDAndLabel(id, id)
	if err != nil {
		return nil, err
	}
	private := public.Copy()
	switch {
	case isRSA(alg):
		// A signing key that also decrypts is one key doing two jobs; the
		// module is told it does one.
		if err := private.Set(crypto11.CkaDecrypt, false); err != nil {
			return nil, err
		}
		return c.GenerateRSAKeyPairWithAttributes(public, private, rsaBits)
	case curveFor(alg) != nil:
		if err := private.Set(crypto11.CkaDerive, false); err != nil {
			return nil, err
		}
		return c.GenerateECDSAKeyPairWithAttributes(public, private, curveFor(alg))
	default:
		return nil, fmt.Errorf("%s keys are not made in a PKCS#11 token here", alg)
	}
}

func (b *pkcs11Backend) Open(name string) (crypto.Signer, error) {
	c, err := b.context()
	if err != nil {
		return nil, err
	}
	found, err := c.FindKeyPairs([]byte(name), []byte(name))
	switch {
	case err != nil:
		return nil, fmt.Errorf("finding it in token %q: %w", b.config.TokenLabel, err)
	case len(found) == 0:
		return nil, fmt.Errorf("token %q holds no key %q", b.config.TokenLabel, name)
	case len(found) > 1:
		// Which one signs would be the module's choice, not this deployment's.
		return nil, fmt.Errorf("token %q holds %d keys named %q", b.config.TokenLabel, len(found), name)
	}
	return found[0], nil
}
