package authzen

import "testing"

// An access evaluation is a policy enforcement point's JSON, decoded strictly. Decoding
// ends in a request or an error, and a reference splits or does not.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`{"subject":{"type":"user","id":"ada"},"action":{"name":"read"},"resource":{"type":"doc","id":"1"}}`,
		`{"subject":{"type":"user","id":"ada"},"subject":{}}`, `{"evaluations":[{}]}`, `{}`, `[`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var req Request
		_ = Decode(body, &req)
		_, _, _ = ParseRef(string(body))
	})
}
