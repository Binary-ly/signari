package keys

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// The address hash is keyed by the root key: the same address under two root
// keys hashes apart, and under neither is it the plain digest a copy of the
// database could reverse by trying every IPv4 address (2.28).
func TestTheAddressHashIsKeyedByTheRootKey(t *testing.T) {
	a, err := NewRootKey("a", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRootKey("b", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const addr = "198.51.100.7"
	if !bytes.Equal(a.AddressHash(addr), a.AddressHash(addr)) {
		t.Fatal("one root key hashed one address two ways, so no two sessions could be compared")
	}
	if bytes.Equal(a.AddressHash(addr), b.AddressHash(addr)) {
		t.Error("two root keys gave the same hash: the key is not in it")
	}
	if bytes.Equal(a.AddressHash(addr), a.AddressHash("198.51.100.8")) {
		t.Error("two addresses gave the same hash")
	}
	plain := sha256.Sum256([]byte(addr))
	if bytes.Equal(a.AddressHash(addr), plain[:]) {
		t.Error("the hash is the unkeyed digest")
	}
}
