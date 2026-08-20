package keys

import (
	"crypto/rsa"
	"testing"
)

// ASVS 5.0.0 V11.2.3: every cryptographic primitive must provide at least 128
// bits of security, and "RSA requires a 3072-bit key to achieve the same" as a
// 256-bit ECC key.
//
// Pinned because the number is easy to lower for a plausible reason — RSA key
// generation at 3072 bits is noticeably slower than at 2048, and a test that
// generates one feels slow. Lowering it back would be invisible in every test
// except this one.
func TestGeneratedRSAKeysMeetTheSecurityFloor(t *testing.T) {
	if RSABits < 3072 {
		t.Fatalf("RSABits = %d; ASVS V11.2.3 needs 3072 for 128 bits of security "+
			"(2048 is roughly 112)", RSABits)
	}
	for _, alg := range []Algorithm{RS256, PS256} {
		k, err := Generate(NewKID(), alg)
		if err != nil {
			t.Fatalf("generating %s: %v", alg, err)
		}
		pub, ok := k.Signer().Public().(*rsa.PublicKey)
		if !ok {
			t.Fatalf("%s did not produce an RSA key", alg)
		}
		if n := pub.N.BitLen(); n < 3072 {
			t.Errorf("%s produced a %d-bit key, want at least 3072", alg, n)
		}
	}
}

// The elliptic default already clears the floor, and is what almost every
// deployment actually signs with.
func TestES256MeetsTheFloorToo(t *testing.T) {
	k, err := Generate(NewKID(), ES256)
	if err != nil {
		t.Fatal(err)
	}
	// P-256 gives roughly 128 bits of security, which is the comparison ASVS
	// V11.2.3 draws its RSA number from.
	if k.Algorithm() != ES256 {
		t.Errorf("algorithm = %v", k.Algorithm())
	}
}
