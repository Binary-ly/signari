// Package ech makes and loads the keys for TLS Encrypted Client Hello (RFC 9849),
// which the public listener uses so that the name a browser asked for is not sent
// in the clear (ASVS 5.0.0 V12.1.5, specs/asvs-5.0.0.txt).
//
// crypto/tls does the handshake (tls.Config.EncryptedClientHelloKeys); what it
// does not do is make the ECHConfig that a key is published as, which is this
// package's: RFC 9849 §4 (specs/rfc9849.txt:277-313) for the structure, RFC 9180
// for the HPKE identifiers. The ECHConfigList it produces is what goes into the
// name's HTTPS record as `ech=`, in Base 64 with its length prefix (RFC 9848 §3,
// specs/rfc9848.txt:101-104).
//
// A key file is two PEM blocks: PRIVATE KEY, the X25519 key as PKCS #8, and
// ECHCONFIG, the ECHConfigList holding that key's one configuration, byte for
// byte what clients are given.
package ech

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const (
	// Version is ECHConfig.version, the encrypted_client_hello code point
	// (specs/rfc9849.txt:311, 317-318).
	Version = 0xfe0d
	// kemX25519 is DHKEM(X25519, HKDF-SHA256) (RFC 9180 §7.1, specs/rfc9180.txt:951).
	kemX25519 = 0x0020
	// kdfHKDFSHA256 is HKDF-SHA256 (RFC 9180 §7.2, specs/rfc9180.txt:1108).
	kdfHKDFSHA256 = 0x0001
	// aeadAES128GCM and aeadChaCha20Poly1305 (RFC 9180 §7.3, specs/rfc9180.txt:1185, 1189).
	aeadAES128GCM        = 0x0001
	aeadChaCha20Poly1305 = 0x0003
)

// Suite is an HpkeSymmetricCipherSuite (specs/rfc9849.txt:282-285).
type Suite struct{ KDF, AEAD uint16 }

// Suites are the ones a key made here offers: both are ones crypto/tls's server
// accepts, and ChaCha20 is the one a client without AES instructions wants.
var Suites = []Suite{{kdfHKDFSHA256, aeadAES128GCM}, {kdfHKDFSHA256, aeadChaCha20Poly1305}}

// Config is the part of an ECHConfig this package reads back.
type Config struct {
	ID            byte
	KEM           uint16
	PublicKey     []byte
	Suites        []Suite
	MaxNameLength byte
	PublicName    string
}

// MarshalConfig is an ECHConfig, version 0xfe0d (specs/rfc9849.txt:277-313).
func MarshalConfig(c Config) ([]byte, error) {
	switch {
	case len(c.PublicKey) == 0 || len(c.PublicKey) > 0xffff:
		return nil, errors.New("an ECH public key is 1 to 65535 bytes")
	case len(c.Suites) == 0 || len(c.Suites)*4 > 0xfffc:
		return nil, errors.New("an ECH configuration offers at least one cipher suite")
	case len(c.PublicName) == 0 || len(c.PublicName) > 255:
		return nil, errors.New("an ECH public name is 1 to 255 bytes")
	}
	// Each length below is held to its field's width by the switch above, or by
	// the check after it for the whole.
	u16 := binary.BigEndian.AppendUint16
	contents := []byte{c.ID}
	contents = u16(contents, c.KEM)
	contents = u16(contents, uint16(len(c.PublicKey))) // #nosec G115 -- at most 0xffff, above
	contents = append(contents, c.PublicKey...)
	contents = u16(contents, uint16(4*len(c.Suites))) // #nosec G115 -- at most 0xfffc, above
	for _, s := range c.Suites {
		contents = u16(u16(contents, s.KDF), s.AEAD)
	}
	contents = append(contents, c.MaxNameLength, byte(len(c.PublicName))) // #nosec G115 -- at most 255, above
	contents = append(contents, c.PublicName...)
	contents = u16(contents, 0) // no extensions
	if len(contents) > 0xffff {
		return nil, errors.New("the ECH configuration is too long")
	}
	return append(u16(u16(nil, Version), uint16(len(contents))), contents...), nil // #nosec G115 -- checked just above
}

// MarshalConfigList is an ECHConfigList, length prefix included
// (specs/rfc9849.txt:379, specs/rfc9848.txt:101-102).
func MarshalConfigList(configs ...[]byte) ([]byte, error) {
	var body []byte
	for _, c := range configs {
		body = append(body, c...)
	}
	if len(body) < 4 || len(body) > 0xffff {
		return nil, errors.New("an ECHConfigList holds 4 to 65535 bytes of configurations")
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...), nil // #nosec G115 -- checked just above
}

// SplitConfigList is the ECHConfigs of a list, each whole, version and length
// included: what tls.EncryptedClientHelloKey.Config takes.
func SplitConfigList(list []byte) ([][]byte, error) {
	if len(list) < 2 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return nil, errors.New("the ECHConfigList's length does not match its contents")
	}
	var out [][]byte
	for rest := list[2:]; len(rest) > 0; {
		if len(rest) < 4 {
			return nil, errors.New("an ECHConfig is cut short")
		}
		n := 4 + int(binary.BigEndian.Uint16(rest[2:]))
		if n > len(rest) {
			return nil, errors.New("an ECHConfig is longer than the list holding it")
		}
		out = append(out, rest[:n])
		rest = rest[n:]
	}
	if len(out) == 0 {
		return nil, errors.New("the ECHConfigList is empty")
	}
	return out, nil
}

// ParseConfig reads an ECHConfig of version 0xfe0d.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	r := bytes.NewReader(b)
	var version, length uint16
	if binary.Read(r, binary.BigEndian, &version) != nil || binary.Read(r, binary.BigEndian, &length) != nil {
		return c, errors.New("an ECHConfig is cut short")
	}
	if version != Version {
		return c, fmt.Errorf("ECHConfig version %#04x, not %#04x", version, Version)
	}
	if int(length) != r.Len() {
		return c, errors.New("the ECHConfig's length does not match its contents")
	}
	id, err := r.ReadByte()
	if err != nil {
		return c, errors.New("an ECHConfig is cut short")
	}
	c.ID = id
	var keyLen, suitesLen uint16
	if binary.Read(r, binary.BigEndian, &c.KEM) != nil || binary.Read(r, binary.BigEndian, &keyLen) != nil {
		return c, errors.New("an ECHConfig is cut short")
	}
	c.PublicKey = make([]byte, keyLen)
	if n, _ := r.Read(c.PublicKey); n != int(keyLen) || binary.Read(r, binary.BigEndian, &suitesLen) != nil ||
		suitesLen%4 != 0 || suitesLen == 0 {
		return c, errors.New("an ECHConfig's key or cipher suites are malformed")
	}
	for i := 0; i < int(suitesLen)/4; i++ {
		var s Suite
		if binary.Read(r, binary.BigEndian, &s) != nil {
			return c, errors.New("an ECHConfig's cipher suites are cut short")
		}
		c.Suites = append(c.Suites, s)
	}
	if c.MaxNameLength, err = r.ReadByte(); err != nil {
		return c, errors.New("an ECHConfig is cut short")
	}
	nameLen, err := r.ReadByte()
	if err != nil || nameLen == 0 {
		return c, errors.New("an ECHConfig has no public name")
	}
	name := make([]byte, nameLen)
	if n, _ := r.Read(name); n != int(nameLen) {
		return c, errors.New("an ECHConfig's public name is cut short")
	}
	c.PublicName = string(name)
	var extLen uint16
	if binary.Read(r, binary.BigEndian, &extLen) != nil || int(extLen) != r.Len() {
		return c, errors.New("an ECHConfig's extensions are malformed")
	}
	return c, nil
}

// CheckPublicName refuses a public name a client would not accept: a DNS name,
// not an address (RFC 9849 §6.1.7, specs/rfc9849.txt:1000-1003), since a client
// that is refused ECH checks the retry configurations against a certificate for
// it.
func CheckPublicName(name string) error {
	if _, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return fmt.Errorf("the public name %q is an address; it must be a DNS name the server holds a certificate for", name)
	}
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("the public name %q is not a fully qualified DNS name", name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("the public name %q has a malformed label", name)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("the public name %q has a character a DNS name cannot", name)
			}
		}
	}
	return nil
}

// Key is one ECH key and the configuration it is published as.
type Key struct {
	Private *ecdh.PrivateKey
	Config  []byte // an ECHConfig
}

// New makes a key for publicName under configID.
func New(publicName string, configID byte) (Key, error) {
	if err := CheckPublicName(publicName); err != nil {
		return Key{}, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	cfg, err := MarshalConfig(Config{ID: configID, KEM: kemX25519, PublicKey: priv.PublicKey().Bytes(),
		Suites: Suites, PublicName: strings.ToLower(publicName)})
	if err != nil {
		return Key{}, err
	}
	return Key{Private: priv, Config: cfg}, nil
}

// List is the ECHConfigList this one key is published as.
func (k Key) List() ([]byte, error) { return MarshalConfigList(k.Config) }

// MarshalPEM is the key file.
func (k Key) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}
	list, err := k.List()
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "ECHCONFIG", Bytes: list})...), nil
}

// ParsePEM reads a key file, and refuses one whose configuration is not its
// key's: a client would encrypt to a key the server does not hold.
func ParsePEM(data []byte) (Key, error) {
	var k Key
	var list []byte
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return k, fmt.Errorf("the ECH private key: %w", err)
			}
			priv, ok := parsed.(*ecdh.PrivateKey)
			if !ok || priv.Curve() != ecdh.X25519() {
				return k, errors.New("the ECH private key is not an X25519 key")
			}
			k.Private = priv
		case "ECHCONFIG":
			list = b.Bytes
		}
	}
	if k.Private == nil || list == nil {
		return k, errors.New("an ECH key file holds a PRIVATE KEY and an ECHCONFIG block")
	}
	configs, err := SplitConfigList(list)
	if err != nil {
		return k, err
	}
	if len(configs) != 1 {
		return k, errors.New("an ECH key file's ECHCONFIG holds the one configuration of its key")
	}
	c, err := ParseConfig(configs[0])
	if err != nil {
		return k, err
	}
	if c.KEM != kemX25519 || !bytes.Equal(c.PublicKey, k.Private.PublicKey().Bytes()) {
		return k, errors.New("the ECH configuration is not this file's private key's")
	}
	k.Config = configs[0]
	return k, nil
}

// Load reads the key files paths names, newest first, for the public listener.
// The first is the one a client refused ECH is told to retry with; the rest are
// still accepted, for clients holding a DNS answer from before it (RFC 9849
// §4.1, specs/rfc9849.txt:387-390). Two with one config_id are refused, since a
// client names the key it used by that id alone.
func Load(paths []string) ([]tls.EncryptedClientHelloKey, []Config, error) {
	var keys []tls.EncryptedClientHelloKey
	var configs []Config
	seen := map[byte]string{}
	for i, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- the operator names the file, as for the TLS key
		if err != nil {
			return nil, nil, fmt.Errorf("reading the ECH key %s: %w", p, err)
		}
		k, err := ParsePEM(data)
		if err != nil {
			return nil, nil, fmt.Errorf("the ECH key %s: %w", p, err)
		}
		c, _ := ParseConfig(k.Config)
		if other, dup := seen[c.ID]; dup {
			return nil, nil, fmt.Errorf("the ECH keys %s and %s share config id %d; make one with another -config-id",
				other, p, c.ID)
		}
		seen[c.ID] = p
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config: k.Config, PrivateKey: k.Private.Bytes(), SendAsRetry: i == 0,
		})
		configs = append(configs, c)
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("no ECH key named")
	}
	return keys, configs, nil
}
