package oid4vp

import (
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// encryptAs is a wallet encrypting its answer to the request's key.
func encryptAs(t *testing.T, to *jose.JSONWebKey, kid string, enc jose.ContentEncryption, payload string) string {
	t.Helper()
	e, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: jose.ECDH_ES, Key: to.Key, KeyID: kid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := e.Encrypt([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnEncryptedAnswerOpensWithItsRequestsKeyAlone(t *testing.T) {
	sealed, public, err := NewResponseKey("state-1")
	if err != nil {
		t.Fatal(err)
	}
	if public.Algorithm != "ECDH-ES" || public.Use != "enc" || public.KeyID != "state-1" || !public.IsPublic() {
		t.Fatalf("published as %+v", public)
	}
	key, err := ParseResponseKey(sealed)
	if err != nil {
		t.Fatal(err)
	}
	const answer = `{"vp_token":{"person":["eyJ...~"]},"state":"state-1"}`

	obj, err := ParseResponse(encryptAs(t, public, "state-1", jose.A128GCM, answer))
	if err != nil {
		t.Fatal(err)
	}
	vp, err := OpenResponse(obj, key, "state-1", "state-1")
	if err != nil || vp != `{"person":["eyJ...~"]}` {
		t.Fatalf("opened %q, %v", vp, err)
	}

	_, other, _ := NewResponseKey("state-2")
	otherKey, _ := ParseResponseKey(func() []byte { s, _, _ := NewResponseKey("x"); return s }())
	for name, c := range map[string]struct {
		jwe        string
		key        bool
		state, err string
	}{
		"to another key":         {jwe: encryptAs(t, other, "state-1", jose.A128GCM, answer), state: "state-1", err: "does not decrypt"},
		"named for another key":  {jwe: encryptAs(t, public, "state-2", jose.A128GCM, answer), state: "state-1", err: "not to this request's key"},
		"for another request":    {jwe: encryptAs(t, public, "state-1", jose.A128GCM, `{"vp_token":{},"state":"x"}`), state: "state-1", err: "another request"},
		"with no vp_token":       {jwe: encryptAs(t, public, "state-1", jose.A128GCM, `{"state":"state-1"}`), state: "state-1", err: "no vp_token"},
		"opened with a stranger": {jwe: encryptAs(t, public, "state-1", jose.A128GCM, answer), key: true, state: "state-1", err: "does not decrypt"},
	} {
		obj, err := ParseResponse(c.jwe)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		k := key
		if c.key {
			k = otherKey
		}
		if _, err := OpenResponse(obj, k, "state-1", c.state); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: got %v, want %q", name, err, c.err)
		}
	}

	// An enc this verifier did not offer is refused before anything is decrypted.
	if _, err := ParseResponse(encryptAs(t, public, "state-1", jose.A256GCM, answer)); err == nil {
		t.Error("A256GCM was taken, and only the default, A128GCM, was offered")
	}
}
