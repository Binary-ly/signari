package tokens

import (
	"strings"
	"testing"

	"signari.dev/engine/internal/keys"
)

// The token verifier is reachable, unauthenticated, from the internet. A panic
// here is a remote denial of service: one malformed Authorization header takes
// the process down, and it costs an attacker nothing to send.
//
// Fuzzing rather than a fixed list because the interesting inputs are the ones
// nobody thought of -- truncated base64, absurd nesting, headers claiming
// algorithms that do not exist, payloads whose declared lengths disagree with
// their contents.
func FuzzVerifyAccessToken(f *testing.F) {
	k, err := keys.Generate(keys.NewKID(), keys.ES256)
	if err != nil {
		f.Fatal(err)
	}
	active, _ := keys.WithState(k, keys.StateActive)
	set, _ := keys.NewSet(active)

	// A real token, so the corpus starts somewhere the parser gets deep into.
	valid, err := NewSigner(active).SignJSON(validClaims(), TypAccessToken)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("..")
	f.Add("a.b.c")
	f.Add(valid[:len(valid)/2])
	f.Add(strings.Repeat("A", 5000))
	f.Add("eyJhbGciOiJub25lIn0..")

	f.Fuzz(func(t *testing.T, raw string) {
		// The contract is total: any input at all yields a value or an error,
		// never a panic and never a hang.
		_, _ = VerifyAccessToken(set, testIssuer, raw)
		_, _ = VerifyIDTokenAudience(set, testIssuer, raw)
		_, _ = VerifyTyped(set, testIssuer, raw, TypAccessToken)
	})
}
