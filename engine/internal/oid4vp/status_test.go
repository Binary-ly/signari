package oid4vp

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"signari.dev/engine/internal/sdjwt"
)

// The lists from the specification itself: §4.1's two worked examples and Appendix
// C's three larger ones (specs/token-status-list.txt:266-332, 2001-2130). Bit order is
// what §11.1 warns implementations get wrong (:935), and these are where it shows.
func TestTheStatusListIsReadAsTheSpecificationWritesIt(t *testing.T) {
	cases := []struct {
		name string
		bits int
		lst  string
		set  map[int64]byte
		size int64
	}{
		{name: "4.1 one bit", bits: 1, lst: "eNrbuRgAAhcBXQ", size: 16,
			set: map[int64]byte{0: 1, 3: 1, 4: 1, 5: 1, 7: 1, 8: 1, 9: 1, 13: 1, 15: 1}},
		{name: "4.1 two bits", bits: 2, lst: "eNo76fITAAPfAgc", size: 12,
			set: map[int64]byte{0: 1, 1: 2, 3: 3, 5: 1, 7: 1, 8: 1, 9: 2, 10: 3, 11: 3}},
		{name: "C.1", bits: 1, size: 1 << 20, lst: "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogE" +
			"AAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAA" +
			"A7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAA" +
			"ACAZC8L2AEb",
			set: map[int64]byte{0: 1, 1993: 1, 25460: 1, 159495: 1, 495669: 1, 554353: 1,
				645645: 1, 723232: 1, 854545: 1, 934534: 1, 1000345: 1}},
		{name: "C.2", bits: 2, size: 1 << 20, lst: "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGV" +
			"IAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9S" +
			"wIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw",
			set: map[int64]byte{0: 1, 1993: 2, 25460: 1, 159495: 3, 495669: 1, 554353: 1,
				645645: 2, 723232: 1, 854545: 1, 934534: 2, 1000345: 3}},
		{name: "C.3", bits: 4, size: 1 << 20, lst: "eNrt0EENgDAQADAIHwImkIIEJEwCUpCEBBQRHOy35Li" +
			"1EjoOQGabAgAAAAAAAAAAAAAAAAAAACC1SQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADrsCAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAADoxaEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIoCgAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACArpwKAAAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAGhqVkAzlwIAAAAAiGVRAAAAAAAAAAAAAAAAAAA" +
			"AAAAAAAAAAAAAAAAAAAAAAABx3AoAgLpVAQAAAAAAAAAAAAAAwM89rwMAAAAAAAAAA" +
			"AjsA9xMBMA",
			set: map[int64]byte{0: 1, 1993: 2, 35460: 3, 459495: 4, 595669: 5, 754353: 6, 845645: 7,
				923232: 8, 924445: 9, 934534: 10, 1004534: 11, 1000345: 12, 1030203: 13, 1030204: 14,
				1030205: 15}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Every place named, and each of their neighbours, which a list with
			// the bit order reversed would read as set.
			for idx := range c.set {
				for _, i := range []int64{idx - 1, idx, idx + 1} {
					if i < 0 || i >= c.size {
						continue
					}
					w, named := c.set[i]
					if !named {
						w = 0
					}
					got, err := statusAt(c.lst, c.bits, i)
					if err != nil {
						t.Fatalf("index %d: %v", i, err)
					}
					if got != w {
						t.Errorf("index %d: got %#x, want %#x", i, got, w)
					}
				}
			}
			// The first place past the end has no status, and is refused (:815).
			if _, err := statusAt(c.lst, c.bits, c.size+int64(8/c.bits)); err == nil ||
				!strings.Contains(err.Error(), "past the list's end") {
				t.Errorf("past the end: %v", err)
			}
		})
	}
}

func TestAStatusListThatIsNotOneIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, lst string
		bits      int
		want      string
	}{
		{name: "three bits", lst: "eNrbuRgAAhcBXQ", bits: 3, want: "not 1, 2, 4 or 8"},
		{name: "not base64url", lst: "eNr/uRgA", bits: 1, want: "not base64url"},
		{name: "not zlib", lst: base64.RawURLEncoding.EncodeToString([]byte("plain")), bits: 1, want: "not a ZLIB stream"},
	} {
		if _, err := statusAt(c.lst, c.bits, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// An index the bound refuses before anything is decompressed.
	if _, err := statusAt("eNrbuRgAAhcBXQ", 1, maxStatusOffset*8); err == nil ||
		!strings.Contains(err.Error(), "beyond what this verifier reads") {
		t.Errorf("a far index: %v", err)
	}
}

// statusList is a §4.2 list of size places at bits each, the ones named set.
func statusList(t *testing.T, bits int, size int, set map[int]byte) string {
	t.Helper()
	raw := make([]byte, size*bits/8)
	for i, v := range set {
		raw[i*bits/8] |= v << (uint(i*bits) % 8)
	}
	var b bytes.Buffer
	w, _ := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

const testStatusURI = "https://issuer.example/statuslists/7"

// statusHost answers for the issuer's list: what it signs, and how many times it
// was asked.
type statusHost struct {
	f           *fixture
	asked       int
	contentType string
	err         error
	token       func() string
}

func (h *statusHost) fetch(uri, accept string) ([]byte, string, error) {
	h.asked++
	if uri != testStatusURI || accept != StatusTokenMedia {
		h.f.t.Errorf("asked for %s as %s", uri, accept)
	}
	if h.err != nil {
		return nil, "", h.err
	}
	return []byte(h.token()), h.contentType, nil
}

// listToken is the issuer's Status List Token, its claims after edit.
func (f *fixture) listToken(set map[int]byte, edit func(map[string]any), typ string) string {
	f.t.Helper()
	claims := map[string]any{"sub": testStatusURI, "iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
		"ttl": 600, "status_list": map[string]any{"bits": 2, "lst": statusList(f.t, 2, 64, set)}}
	if edit != nil {
		edit(claims)
	}
	return signJSON(f.t, f.issuerKey, typ, "issuer-1", claims)
}

// withStatus is a presentation of a credential at place 5 of the list.
func (f *fixture) withStatus(edit func(map[string]any)) string {
	c := f.credential(func(p map[string]any) {
		p["status"] = map[string]any{"status_list": map[string]any{"idx": 5, "uri": testStatusURI}}
		if edit != nil {
			edit(p)
		}
	}, nil, "dc+sd-jwt")
	return token("person", f.present(c, both, nil, nil))
}

func TestAValidStatusAdmits(t *testing.T) {
	f := newFixture(t)
	h := &statusHost{f: f, contentType: StatusTokenMedia + "; charset=utf-8",
		token: func() string {
			return f.listToken(map[int]byte{4: statusInvalid, 6: statusSuspended}, nil, "statuslist+jwt")
		}}
	e := f.expect()
	e.Fetch = h.fetch
	if _, err := Verify(f.withStatus(nil), e); err != nil {
		t.Fatal(err)
	}
	if h.asked != 1 {
		t.Errorf("the list was asked for %d times", h.asked)
	}
	// A credential that names no status is not looked up anywhere.
	if _, err := Verify(token("person", f.present(f.credential(nil, nil, "dc+sd-jwt"), both, nil, nil)), e); err != nil {
		t.Fatal(err)
	}
	if h.asked != 1 {
		t.Error("a credential without a status had its status looked up")
	}
}

func TestAStatusThatIsNotValidRefuses(t *testing.T) {
	f := newFixture(t)
	other := genKey(t)
	good := func(set map[int]byte) func() string {
		return func() string { return f.listToken(set, nil, "statuslist+jwt") }
	}
	edited := func(edit func(map[string]any)) func() string {
		return func() string { return f.listToken(nil, edit, "statuslist+jwt") }
	}
	cases := []struct {
		name        string
		token       func() string
		contentType string
		err         error
		credential  func(map[string]any)
		noFetcher   bool
		want        string
	}{
		{name: "revoked", token: good(map[int]byte{5: statusInvalid}), want: "revoked"},
		{name: "suspended", token: good(map[int]byte{5: statusSuspended}), want: "suspended"},
		{name: "application specific", token: good(map[int]byte{5: 0x03}), want: "does not accept"},
		{name: "a list for other credentials",
			token: edited(func(c map[string]any) { c["sub"] = "https://issuer.example/statuslists/8" }), want: "is for"},
		{name: "an expired list",
			token: edited(func(c map[string]any) { c["exp"] = f.now.Add(-time.Hour).Unix() }), want: "expired"},
		{name: "a list from the future",
			token: edited(func(c map[string]any) { c["iat"] = f.now.Add(time.Hour).Unix() }), want: "in the future"},
		{name: "a list not yet valid",
			token: edited(func(c map[string]any) { c["nbf"] = f.now.Add(time.Hour).Unix() }), want: "not valid until"},
		{name: "a list without iat",
			token: edited(func(c map[string]any) { delete(c, "iat") }), want: "no iat"},
		{name: "a zero ttl",
			token: edited(func(c map[string]any) { c["ttl"] = 0 }), want: "ttl"},
		{name: "no status_list",
			token: edited(func(c map[string]any) { delete(c, "status_list") }), want: "no status_list"},
		{name: "signed by somebody else",
			token: func() string {
				return signJSON(t, other, "statuslist+jwt", "issuer-1", map[string]any{"sub": testStatusURI,
					"iat": f.now.Unix(), "status_list": map[string]any{"bits": 1, "lst": statusList(t, 1, 64, nil)}})
			}, want: "does not verify with the issuer's keys"},
		{name: "a JWT that is not a list",
			token: func() string { return f.listToken(nil, nil, "JWT") }, want: "typ"},
		{name: "served as something else", contentType: "application/jwt", token: good(nil), want: "came as"},
		{name: "unreachable", err: errors.New("connection refused"), want: "could not be read"},
		{name: "no way to read it", noFetcher: true, want: "no way to read it"},
		{name: "a place past the list's end", token: good(nil),
			credential: func(p map[string]any) {
				p["status"] = map[string]any{"status_list": map[string]any{"idx": 64, "uri": testStatusURI}}
			}, want: "past the list's end"},
		{name: "a status kept some other way",
			credential: func(p map[string]any) { p["status"] = map[string]any{"other_mechanism": map[string]any{}} },
			want:       "does not read"},
		{name: "a list at a plain http address",
			credential: func(p map[string]any) {
				p["status"] = map[string]any{"status_list": map[string]any{"idx": 5, "uri": "http://issuer.example/l"}}
			}, want: "https"},
		{name: "a negative place",
			credential: func(p map[string]any) {
				p["status"] = map[string]any{"status_list": map[string]any{"idx": -1, "uri": testStatusURI}}
			}, want: "non-negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct := c.contentType
			if ct == "" {
				ct = StatusTokenMedia
			}
			h := &statusHost{f: f, contentType: ct, err: c.err, token: c.token}
			e := f.expect()
			if !c.noFetcher {
				e.Fetch = h.fetch
			}
			_, err := Verify(f.withStatus(c.credential), e)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error saying %q", err, c.want)
			}
		})
	}
}

// A credential refused for anything else is not looked up: "further procedures
// regarding Status List MUST NOT be performed" (specs/token-status-list.txt:789). So a
// stranger cannot make this verifier fetch whatever a credential names.
func TestAnInvalidCredentialIsNotLookedUp(t *testing.T) {
	f := newFixture(t)
	h := &statusHost{f: f, contentType: StatusTokenMedia,
		token: func() string { return f.listToken(nil, nil, "statuslist+jwt") }}
	e := f.expect()
	e.Fetch = h.fetch
	e.Nonce = "another request's"
	if _, err := Verify(f.withStatus(nil), e); err == nil {
		t.Fatal("accepted")
	}
	if h.asked != 0 {
		t.Errorf("a presentation that failed was looked up %d times", h.asked)
	}
}

// A claim the profile forbids disclosing, disclosed, refuses the credential: its issuer
// let any holder leave it out, and with status that would be leaving out revocation.
func TestAClaimThatMustBeSignedIsRefusedFromADisclosure(t *testing.T) {
	for name, value := range map[string]any{
		"status": map[string]any{"status_list": map[string]any{"idx": 5, "uri": testStatusURI}},
		"exp":    time.Now().Add(time.Hour).Unix(),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			delete(f.always, name)
			h := &statusHost{f: f, contentType: StatusTokenMedia,
				token: func() string { return f.listToken(nil, nil, "statuslist+jwt") }}
			e := f.expect()
			e.Fetch = h.fetch
			cred := f.credentialDisclosing(name, value)
			_, err := Verify(token("person", f.present(cred, append([]string{name}, both...), nil, nil)), e)
			if err == nil || !strings.Contains(err.Error(), "forbids disclosing") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// credentialDisclosing is the fixture's credential with one more disclosure, name,
// made by hand: sdjwt refuses to make one of the profile's signed claims
// disclosable, and this is what an issuer that did not refuse would hand out.
func (f *fixture) credentialDisclosing(name string, value any) credential {
	f.t.Helper()
	payload, ds, err := sdjwt.Payload(f.always, f.selected)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := json.Marshal([]any{"bm90LWEtcmVhbC1zYWx0", name, value})
	if err != nil {
		f.t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	d, err := sdjwt.Parse(encoded)
	if err != nil {
		f.t.Fatal(err)
	}
	digests, ok := payload["_sd"].([]string)
	if !ok {
		f.t.Fatalf("_sd is a %T", payload["_sd"])
	}
	payload["_sd"] = append(digests, d.Digest())
	payload["cnf"] = map[string]any{"jwk": jose.JSONWebKey{Key: f.holderKey.Public()}}
	return credential{jwt: signJSON(f.t, f.issuerKey, "dc+sd-jwt", "issuer-1", payload), disclosures: append(ds, d)}
}
