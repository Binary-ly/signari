package jsonstrict

import (
	"encoding/json"
	"testing"
)

// Every JSON body this server takes passes through here first. It ends in an answer for
// any input (malformed JSON is left to the caller's decoder, as the package says), and a
// member named twice is always seen: whatever valid value comes first, an object naming
// "k" again after it is refused.
func FuzzNoDuplicateKeys(f *testing.F) {
	for _, s := range []string{`{"a":1,"b":[{"c":2}]}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`,
		`[{"x":1},{"x":2}]`, `{"a":1,"a":2}`, `{`, ``, `"s"`, `[[[[[[`, `"\"k\""`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_ = NoDuplicateKeys(body)
		if !json.Valid(body) {
			return
		}
		doubled := append(append([]byte(`{"k":`), body...), []byte(`,"k":1}`)...)
		if NoDuplicateKeys(doubled) == nil {
			t.Fatalf("a member named twice after %q was not seen", body)
		}
	})
}
