package tokens

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
)

// Every algorithm a key can be made for signs a token this engine accepts, and says so in
// the header, so an algorithm cannot be added to the list and left out of a switch: the
// signer, the verifier and at_hash each have one (9.04).
func TestEveryAlgorithmSignsWhatTheEngineVerifies(t *testing.T) {
	for _, alg := range keys.AllAlgorithms {
		k, err := keys.Generate(keys.NewKID(), alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		active, err := keys.WithState(k, keys.StateActive)
		if err != nil {
			t.Fatal(err)
		}
		set, err := keys.NewSet(active)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := NewSigner(active).SignJSON(validClaims(), TypAccessToken)
		if err != nil {
			t.Errorf("%s did not sign: %v", alg, err)
			continue
		}
		if _, err := VerifyAccessToken(set, testIssuer, raw); err != nil {
			t.Errorf("%s did not verify: %v", alg, err)
		}
		header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(raw, ".", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		var h struct {
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(header, &h); err != nil {
			t.Fatal(err)
		}
		if h.Alg != string(alg) {
			t.Errorf("%s signed a token whose header says %s", alg, h.Alg)
		}
		if got, err := AtHash(alg, "an-access-token"); err != nil || (got == "" && alg != keys.EdDSA) {
			t.Errorf("%s: at_hash %q, %v", alg, got, err)
		}
	}
}

// at_hash is the left half of the hash the signature used: taking SHA-256 of a token signed
// with SHA-384 gives a value every conforming client refuses for a reason nobody can see.
func TestAtHashIsTheLeftHalfOfTheAlgorithmsOwnHash(t *testing.T) {
	const token = "an-access-token"
	s256 := sha256.Sum256([]byte(token))
	s384 := sha512.Sum384([]byte(token))
	s512 := sha512.Sum512([]byte(token))
	enc := base64.RawURLEncoding.EncodeToString
	for _, c := range []struct {
		alg  keys.Algorithm
		want string
	}{
		{keys.ES256, enc(s256[:16])}, {keys.RS256, enc(s256[:16])}, {keys.PS256, enc(s256[:16])},
		{keys.ES384, enc(s384[:24])}, {keys.RS384, enc(s384[:24])}, {keys.PS384, enc(s384[:24])},
		{keys.ES512, enc(s512[:32])}, {keys.RS512, enc(s512[:32])}, {keys.PS512, enc(s512[:32])},
	} {
		if got, err := AtHash(c.alg, token); err != nil || got != c.want {
			t.Errorf("%s: %q, %v, want %q", c.alg, got, err, c.want)
		}
	}
}
