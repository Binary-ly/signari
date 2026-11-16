package jsonstrict

import (
	"testing"
	"time"
)

// Malformed JSON inside an array or an object ends the walk and is answered as nil, left
// to the caller's decoder. It spun forever: each level answered its failed token with nil,
// and the loop around it asked again at the byte it could not read (found by
// internal/authzen's FuzzDecode with `{"evaluations":[{}R}`). A body this short pinned a
// core on every endpoint that reads JSON through here.
func TestMalformedJSONEndsTheWalk(t *testing.T) {
	for _, body := range []string{
		`{"evaluations":[{}R}`, `[{}R]`, `{"a":{}R}`, `[[1]R`, `{"a":[1,R`, `{"a":1 R}`, `[{"k":}]`, `{1:2}`,
	} {
		done := make(chan error, 1)
		go func() { done <- NoDuplicateKeys([]byte(body)) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: %v, and malformed JSON is the caller's to report", body, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: still walking after two seconds", body)
		}
	}
	// A duplicate before the malformed part is still reported.
	if NoDuplicateKeys([]byte(`{"a":1,"a":2,R`)) == nil {
		t.Error("a member named twice before a malformed tail was not seen")
	}
}
