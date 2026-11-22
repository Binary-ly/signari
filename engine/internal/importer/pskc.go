package importer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6030 §6.1.1 names HMAC-SHA1 as the MAC to implement.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	"signari.dev/engine/internal/mfa"
)

// A vendor's file of hardware tokens: Portable Symmetric Key Container, RFC 6030
// (specs/rfc6030.txt). One file holds a batch's seeds, usually sealed under a key the
// vendor sent another way. What comes out is seeds and serial numbers, and nothing is
// stored here: a token still has to show a code before it is anybody's.

const (
	pskcHOTP = "urn:ietf:params:xml:ns:keyprov:pskc:hotp"
	// pskcTOTP is not in RFC 6030, whose §10 registers only HOTP and PIN, nor in anything
	// in specs/. It is what time-based tokens' files carry, and it is the same prefix.
	pskcTOTP = "urn:ietf:params:xml:ns:keyprov:pskc:totp"

	// pskcLimit is more than the largest batch anybody ships: about 700 bytes a token.
	pskcLimit = 64 << 20
)

// PSKCToken is one token in a file.
type PSKCToken struct {
	// Serial is what is printed on the token: <SerialNo>, or the key's Id if a file has none.
	Serial string
	HOTP   bool
	Seed   []byte
	Params mfa.Params
}

type pskcCipherData struct {
	Method struct {
		Algorithm string `xml:"Algorithm,attr"`
	} `xml:"EncryptionMethod"`
	Value string `xml:"CipherData>CipherValue"`
}

type pskcValue struct {
	Plain     *string         `xml:"PlainValue"`
	Encrypted *pskcCipherData `xml:"EncryptedValue"`
	MAC       string          `xml:"ValueMAC"`
}

type pskcContainer struct {
	Version       string `xml:"Version,attr"`
	EncryptionKey *struct {
		Derived *struct{} `xml:"DerivedKey"`
		Name    string    `xml:"KeyName"`
	} `xml:"EncryptionKey"`
	MACMethod *struct {
		Algorithm string          `xml:"Algorithm,attr"`
		Key       *pskcCipherData `xml:"MACKey"`
	} `xml:"MACMethod"`
	Packages []struct {
		Serial string `xml:"DeviceInfo>SerialNo"`
		Keys   []struct {
			ID        string `xml:"Id,attr"`
			Algorithm string `xml:"Algorithm,attr"`
			Suite     string `xml:"AlgorithmParameters>Suite"`
			Response  *struct {
				Length   int    `xml:"Length,attr"`
				Encoding string `xml:"Encoding,attr"`
			} `xml:"AlgorithmParameters>ResponseFormat"`
			Secret   *pskcValue `xml:"Data>Secret"`
			Interval *pskcValue `xml:"Data>TimeInterval"`
		} `xml:"Key"`
	} `xml:"KeyPackage"`
}

// ParsePSKC reads a file. key is the pre-shared key its secrets are sealed under, nil for
// a file that holds them in the clear. A token this cannot use refuses the file: a batch
// half read would leave somebody's token unaccounted for and nobody told.
func ParsePSKC(r io.Reader, key []byte) ([]PSKCToken, error) {
	raw, err := io.ReadAll(io.LimitReader(r, pskcLimit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > pskcLimit {
		return nil, errors.New("that file is too large to be a batch of tokens")
	}
	var file pskcContainer
	if err := xml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("the file is not a PSKC document: %w", err)
	}
	// §1.2: "The major version number should be incremented only if the message format
	// ... has changed so dramatically" that this could not read it.
	if major, _, _ := strings.Cut(file.Version, "."); major != "1" {
		return nil, fmt.Errorf("PSKC version %q is not one this reads", file.Version)
	}
	if file.EncryptionKey != nil && file.EncryptionKey.Derived != nil {
		return nil, errors.New("the file's secrets are sealed under a passphrase, which this does not read; " +
			"ask the vendor for a pre-shared key")
	}
	macKey, mac, err := file.macKey(key)
	if err != nil {
		return nil, err
	}

	var out []PSKCToken
	seen := map[string]bool{}
	for _, pkg := range file.Packages {
		for _, k := range pkg.Keys {
			serial := strings.TrimSpace(pkg.Serial)
			if serial == "" {
				serial = strings.TrimSpace(k.ID)
			}
			if serial == "" || seen[serial] {
				return nil, fmt.Errorf("token %q has no serial number of its own", serial)
			}
			seen[serial] = true
			t := PSKCToken{Serial: serial, Params: mfa.Params{Algorithm: mfa.SHA1, Digits: 6, Period: 30 * time.Second}}
			switch k.Algorithm {
			case pskcHOTP:
				t.HOTP = true
			case pskcTOTP:
			default:
				return nil, fmt.Errorf("token %s is an %q, which is not one this reads", serial, k.Algorithm)
			}
			if k.Response != nil {
				// §10.1 has an HOTP token's format "DECIMAL".
				if k.Response.Encoding != "DECIMAL" {
					return nil, fmt.Errorf("token %s shows %s codes, and only decimal ones can be typed here", serial, k.Response.Encoding)
				}
				t.Params.Digits = k.Response.Length
			}
			if suite := strings.ToUpper(strings.TrimSpace(k.Suite)); suite != "" {
				t.Params.Algorithm = mfa.Algorithm(strings.TrimPrefix(suite, "HMAC-"))
			}
			if k.Interval != nil && k.Interval.Plain != nil {
				seconds, err := strconv.Atoi(strings.TrimSpace(*k.Interval.Plain))
				if err != nil || seconds <= 0 {
					return nil, fmt.Errorf("token %s has an interval of %q", serial, *k.Interval.Plain)
				}
				t.Params.Period = time.Duration(seconds) * time.Second
			}
			if err := t.Params.Check(); err != nil {
				return nil, fmt.Errorf("token %s: %w", serial, err)
			}
			if k.Secret == nil {
				return nil, fmt.Errorf("token %s has no secret in the file", serial)
			}
			if t.Seed, err = k.Secret.open(key, macKey, mac); err != nil {
				return nil, fmt.Errorf("token %s: %w", serial, err)
			}
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("there are no tokens in that file")
	}
	return out, nil
}

// macKey is the key §6.1.1 has the sender put in the file, sealed like the secrets.
func (f pskcContainer) macKey(key []byte) ([]byte, func() hash.Hash, error) {
	if f.MACMethod == nil || f.MACMethod.Key == nil {
		return nil, nil, nil
	}
	if key == nil {
		return nil, nil, errors.New("the file's secrets are sealed; give the key the vendor sent with -key-file")
	}
	var mac func() hash.Hash
	switch f.MACMethod.Algorithm {
	case "http://www.w3.org/2000/09/xmldsig#hmac-sha1":
		// The module panics on this rather than refusing it.
		if fips140.Enforced() {
			return nil, nil, errors.New("the file's MAC is HMAC-SHA1, which fips140=only refuses; " +
				"read it once on a build without that setting, or ask the vendor for HMAC-SHA256")
		}
		mac = sha1.New
	case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256":
		mac = sha256.New
	case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512":
		mac = sha512.New
	default:
		return nil, nil, fmt.Errorf("the MAC %q is not one this reads", f.MACMethod.Algorithm)
	}
	macKey, _, err := f.MACMethod.Key.decrypt(key)
	return macKey, mac, err
}

// open is a value in the clear, or sealed and MACed as §6.1 has it.
func (v *pskcValue) open(key, macKey []byte, mac func() hash.Hash) ([]byte, error) {
	if v.Plain != nil {
		out, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(*v.Plain), ""))
		if err != nil {
			return nil, fmt.Errorf("the secret is not base64: %w", err)
		}
		return out, nil
	}
	if v.Encrypted == nil {
		return nil, errors.New("the secret is neither in the clear nor sealed")
	}
	if key == nil {
		return nil, errors.New("the secret is sealed; give the key the vendor sent with -key-file")
	}
	// §6.1.1: with a cipher that has no integrity check of its own "a keyed-MAC value
	// MUST be placed in the <ValueMAC> element". A wrong key would otherwise come out as
	// a wrong seed about one time in 256, and pass the padding check.
	if macKey == nil {
		return nil, errors.New("the secret has no MAC to check it by")
	}
	plain, sealed, err := v.Encrypted.decrypt(key)
	if err != nil {
		return nil, err
	}
	want, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v.MAC), ""))
	if err != nil {
		return nil, fmt.Errorf("the MAC is not base64: %w", err)
	}
	m := hmac.New(mac, macKey)
	m.Write(sealed)
	if !hmac.Equal(m.Sum(nil), want) {
		return nil, errors.New("the secret does not match its MAC: the wrong key, or a file that was changed")
	}
	return plain, nil
}

// decrypt is AES-CBC with the IV first and PKCS #5 padding, §6.1, answering the plaintext
// and the bytes the MAC covers.
func (c pskcCipherData) decrypt(key []byte) (plain, sealed []byte, err error) {
	want := map[string]int{"http://www.w3.org/2001/04/xmlenc#aes128-cbc": 16,
		"http://www.w3.org/2001/04/xmlenc#aes192-cbc": 24, "http://www.w3.org/2001/04/xmlenc#aes256-cbc": 32}[c.Method.Algorithm]
	if want == 0 {
		return nil, nil, fmt.Errorf("the cipher %q is not one this reads", c.Method.Algorithm)
	}
	if len(key) != want {
		return nil, nil, fmt.Errorf("the key is %d bytes and the file wants %d", len(key), want)
	}
	sealed, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Value), ""))
	if err != nil {
		return nil, nil, fmt.Errorf("the sealed value is not base64: %w", err)
	}
	if len(sealed) < 2*aes.BlockSize || len(sealed)%aes.BlockSize != 0 {
		return nil, nil, errors.New("the sealed value is the wrong length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, len(sealed)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, sealed[:aes.BlockSize]).CryptBlocks(out, sealed[aes.BlockSize:])
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) || !bytes.Equal(out[len(out)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, nil, errors.New("the sealed value does not unpad: the wrong key")
	}
	return out[:len(out)-pad], sealed, nil
}
