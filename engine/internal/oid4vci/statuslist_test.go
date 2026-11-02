package oid4vci

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func statusBytes(t *testing.T, lst string) []byte {
	t.Helper()
	compressed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// §4.1's example, specs/token-status-list.txt:262-297: sixteen statuses, 0xB9 0xA3, and
// §4.2's encoded form of them. What a deflater emits is its own business, so the check is
// that the same bytes come out of both.
func TestTheStatusListIsTheSpecificationsExample(t *testing.T) {
	lst, err := EncodeStatusList(16, []int{0, 3, 4, 5, 7, 8, 9, 13, 15})
	if err != nil {
		t.Fatal(err)
	}
	got, want := statusBytes(t, lst), statusBytes(t, "eNrbuRgAAhcBXQ")
	if !bytes.Equal(got, want) || !bytes.Equal(got, []byte{0xb9, 0xa3}) {
		t.Errorf("got %x, the specification's example is %x", got, want)
	}
}

func TestAPlaceOutsideTheListIsRefused(t *testing.T) {
	for _, index := range []int{-1, 16} {
		if _, err := EncodeStatusList(16, []int{index}); err == nil {
			t.Errorf("index %d was accepted", index)
		}
	}
}

// §5.1, each claim it names and the header's typ.
func TestTheStatusListTokenCarriesWhatTheSpecificationNames(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var payload []byte
	var typ string
	token, err := StatusListToken("https://issuer.test/oid4vci/status/1", "https://issuer.test", []int{3}, now,
		func(p []byte, kind string) (string, error) {
			payload, typ = p, kind
			return "signed", nil
		})
	if err != nil || token != "signed" {
		t.Fatalf("%q %v", token, err)
	}
	if typ != "statuslist+jwt" {
		t.Errorf("typ is %q: §5.1 has it MUST be statuslist+jwt", typ)
	}
	var got struct {
		Iss, Sub string
		Iat, Exp int64
		TTL      int `json:"ttl"`
		List     struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sub != "https://issuer.test/oid4vci/status/1" {
		t.Errorf("sub is %q: §5.1 has it equal the uri a credential carries", got.Sub)
	}
	if got.Iat != now.Unix() || got.Exp <= got.Iat {
		t.Errorf("iat %d exp %d", got.Iat, got.Exp)
	}
	if got.TTL <= 0 {
		t.Errorf("ttl is %d: §5.1 has it a positive number", got.TTL)
	}
	if got.List.Bits != 1 {
		t.Errorf("bits is %d", got.List.Bits)
	}
	statuses := statusBytes(t, got.List.Lst)
	if len(statuses)*8 != StatusListEntries {
		t.Errorf("%d bytes for %d places", len(statuses), StatusListEntries)
	}
	if statuses[0] != 1<<3 {
		t.Errorf("the first byte is %08b", statuses[0])
	}
}

// §6.2's place in both formats, and never where it can be held back: SD-JWT VC lists
// status among the claims that "MUST NOT be included in the Disclosures".
func TestACredentialCarriesItsPlace(t *testing.T) {
	place := &StatusPlace{Index: 7, URI: "https://issuer.test/oid4vci/status/1"}
	var signed []byte
	issuer := Issuer{CredentialIssuer: "https://issuer.test", Status: place,
		Sign: func(p []byte, _ string) (string, error) { signed = p; return "x", nil }}
	for _, format := range []string{FormatSDJWTVC, FormatJWTVC} {
		cfg := Configuration{ID: "Identity", Format: format, VCT: "https://issuer.test/id", AlwaysClaims: []string{"sub"}}
		if _, err := issuer.Issue(cfg, map[string]any{"sub": "u-1"}, testKey(t), time.Now()); err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Status struct {
				List struct {
					Idx int    `json:"idx"`
					URI string `json:"uri"`
				} `json:"status_list"`
			} `json:"status"`
		}
		if err := json.Unmarshal(signed, &claims); err != nil {
			t.Fatal(err)
		}
		if claims.Status.List.Idx != 7 || claims.Status.List.URI != place.URI {
			t.Errorf("%s carries %s", format, signed)
		}
	}
	issuer.Status = nil
	cfg := Configuration{ID: "Identity", Format: FormatSDJWTVC, VCT: "https://issuer.test/id", AlwaysClaims: []string{"sub"}}
	if _, err := issuer.Issue(cfg, map[string]any{"sub": "u-1"}, testKey(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(signed), `"status"`) {
		t.Errorf("a credential with no place carries one: %s", signed)
	}
}
