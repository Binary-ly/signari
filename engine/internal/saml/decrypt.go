package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// What comes back from an upstream that encrypts (8.04). EncryptAssertion is the
// other direction, and offers less: what is sent here is chosen by this project,
// and what is received is chosen by somebody else's product.
const (
	algAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	algAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	algAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	algRSA15     = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	algMGF1SHA1  = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
)

// EncryptionMethods are the algorithms a provider may encrypt to this deployment
// with, for its metadata: the first it can do, in this order.
var EncryptionMethods = []string{algAES256GCM, algAES128GCM, algRSAOAEP, algRSAOAEPMGF1P}

// open decrypts one EncryptedAssertion or EncryptedID and returns what it held,
// with nothing yet believed about it.
//
// # Why CBC is taken here and never sent
//
// The attack on CBC in XML Encryption (see EncryptAssertion) needs a receiver that
// decrypts what an attacker has altered and says what became of it. Nothing can
// alter what a verified signature covers, so behind one the receiver is no oracle.
// There is a provider that encrypts with CBC and nothing else, so refusing it
// outright would refuse it encryption, which is worse than this. authenticated says
// a signature over the ciphertext has been checked already, and without one CBC is
// refused before anything is decrypted.
//
// # Why RSA PKCS#1 v1.5 is not
//
// It is an oracle of its own, Bleichenbacher's, and on the key rather than on one
// message, and no signature over a document changes what the key will do for
// somebody who sends it another.
func open(wrapper *etree.Element, keys []crypto.Decrypter, authenticated bool) ([]byte, error) {
	data := wrapper.FindElement("./EncryptedData")
	if data == nil {
		return nil, errors.New("the encrypted element has no EncryptedData")
	}
	method := data.FindElement("./EncryptionMethod")
	if method == nil {
		return nil, errors.New("the EncryptedData names no algorithm")
	}
	alg := method.SelectAttrValue("Algorithm", "")
	var size int
	gcm := true
	switch alg {
	case algAES128GCM:
		size = 16
	case algAES256GCM:
		size = 32
	case algAES128CBC, algAES256CBC:
		size, gcm = 16, false
		if alg == algAES256CBC {
			size = 32
		}
		if !authenticated {
			return nil, errors.New("the assertion is encrypted with CBC and no signature covers the " +
				"ciphertext; CBC is decrypted only behind a signature, so the upstream has to sign the " +
				"response or encrypt with AES-GCM")
		}
	default:
		return nil, fmt.Errorf("the assertion is encrypted with %q, which is not taken here", alg)
	}

	wrapped, err := wrappedKey(wrapper, data)
	if err != nil {
		return nil, err
	}
	session, err := unwrapKey(wrapped, keys)
	if err != nil {
		return nil, err
	}
	if len(session) != size {
		return nil, fmt.Errorf("the key inside is %d bytes, and %s needs %d", len(session), alg, size)
	}
	raw, err := cipherValue(data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(session)
	if err != nil {
		return nil, err
	}
	if gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(raw) < aead.NonceSize()+aead.Overhead() {
			return nil, errors.New("the ciphertext is too short to be AES-GCM")
		}
		plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
		if err != nil {
			return nil, errors.New("the ciphertext did not authenticate")
		}
		return plain, nil
	}
	return openCBC(block, raw)
}

// openCBC decrypts in XML Encryption's layout: the IV first, and padding whose last
// byte says how long it is and whose others are nobody's business (XML Encryption
// §5.2).
func openCBC(block cipher.Block, raw []byte) ([]byte, error) {
	n := block.BlockSize()
	if len(raw) < 2*n || len(raw)%n != 0 {
		return nil, errors.New("the ciphertext is not whole AES-CBC blocks")
	}
	plain := make([]byte, len(raw)-n)
	cipher.NewCBCDecrypter(block, raw[:n]).CryptBlocks(plain, raw[n:])
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > n {
		return nil, errors.New("the ciphertext has no valid padding")
	}
	return plain[:len(plain)-pad], nil
}

// wrappedKey finds the EncryptedKey, which is inside the EncryptedData's KeyInfo or
// beside it in the wrapper, as a provider prefers.
func wrappedKey(wrapper, data *etree.Element) (*etree.Element, error) {
	if k := data.FindElement("./KeyInfo/EncryptedKey"); k != nil {
		return k, nil
	}
	if k := wrapper.FindElement("./EncryptedKey"); k != nil {
		return k, nil
	}
	return nil, errors.New("the encrypted element carries no key")
}

// unwrapKey opens the session key with whichever live key it was encrypted to.
// Trying each is the plan, since the certificate named in a document is a claim, and
// a provider mid-rotation may name either. OAEP, so that one key failing says nothing.
func unwrapKey(wrapped *etree.Element, keys []crypto.Decrypter) ([]byte, error) {
	method := wrapped.FindElement("./EncryptionMethod")
	if method == nil {
		return nil, errors.New("the EncryptedKey names no algorithm")
	}
	opts := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
	digest := method.FindElement("./DigestMethod")
	switch alg := method.SelectAttrValue("Algorithm", ""); alg {
	case algRSAOAEPMGF1P:
	case algRSAOAEP:
		if mgf := method.FindElement("./MGF"); mgf != nil {
			switch mgf.SelectAttrValue("Algorithm", "") {
			case algMGF1SHA1:
			case algMGF1SHA256:
				opts.MGFHash = crypto.SHA256
			default:
				return nil, fmt.Errorf("the key is wrapped with a mask function that is not taken here: %q",
					mgf.SelectAttrValue("Algorithm", ""))
			}
		}
	case algRSA15:
		return nil, errors.New("the key is wrapped with RSA PKCS#1 v1.5, which is refused: the upstream has to use RSA-OAEP")
	default:
		return nil, fmt.Errorf("the key is wrapped with %q, which is not taken here", alg)
	}
	if digest != nil {
		switch digest.SelectAttrValue("Algorithm", "") {
		case algSHA1Digest:
		case algSHA256:
			opts.Hash = crypto.SHA256
		default:
			return nil, fmt.Errorf("the key is wrapped with a digest that is not taken here: %q",
				digest.SelectAttrValue("Algorithm", ""))
		}
	}
	raw, err := cipherValue(wrapped)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if session, err := k.Decrypt(rand.Reader, raw, opts); err == nil {
			return session, nil
		}
	}
	return nil, errors.New("the key inside was not encrypted to any live key for this upstream")
}

func cipherValue(e *etree.Element) ([]byte, error) {
	v := e.FindElement("./CipherData/CipherValue")
	if v == nil {
		return nil, errors.New("the encrypted element has no CipherValue")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v.Text()), ""))
	if err != nil {
		return nil, fmt.Errorf("the CipherValue is not base64: %w", err)
	}
	return raw, nil
}

// decrypted reads what open returned as a document holding one element named tag,
// with the guards any document from outside gets: decryption does not make it ours.
// inScope is the element the ciphertext stood in, whose namespace declarations the
// plaintext may rely on.
func decrypted(plain []byte, tag string, inScope *etree.Element) (*etree.Document, *etree.Element, error) {
	if err := scanForUnsafeConstructs(plain); err != nil {
		return nil, nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(bytes.TrimSpace(plain)); err != nil {
		return nil, nil, fmt.Errorf("the decrypted %s does not parse: %w", tag, err)
	}
	root := doc.Root()
	if root == nil || root.Tag != tag {
		return nil, nil, fmt.Errorf("what was encrypted is not a %s", tag)
	}
	for e := inScope; e != nil; e = e.Parent() {
		for _, a := range e.Attr {
			if (a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns")) && root.SelectAttr(a.FullKey()) == nil {
				root.CreateAttr(a.FullKey(), a.Value)
			}
		}
	}
	return doc, root, nil
}
