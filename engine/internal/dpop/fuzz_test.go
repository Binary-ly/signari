package dpop

import (
	"testing"
	"time"
)

// A DPoP proof is a header any client sends with a token request or a resource call,
// read before anything about the client is known. Verifying ends in a proof or an error.
func FuzzVerify(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7fX0.e30.AAAA", "POST", "https://as.example/token", "")
	f.Add("a.b.c", "GET", "https://rs.example/r", "token")
	f.Add("", "", "", "")
	f.Add("..", "POST", "::", "x")
	now := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, header, method, uri, accessToken string) {
		_, _ = Verify(header, method, uri, accessToken, now)
	})
}
