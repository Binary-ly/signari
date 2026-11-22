package safedial

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// What is too long is not sent, which a count at the far end says and an error here
// does not. The value of a field is not repeated in the error: it may be a credential.
func TestAnOverlongRequestIsNotSent(t *testing.T) {
	var arrived atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { arrived.Add(1) }))
	t.Cleanup(srv.Close)
	client := ClientAllowing(5*time.Second, netip.MustParsePrefix("127.0.0.0/8"))
	send := func(uri, field string) error {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			t.Fatal(err)
		}
		if field != "" {
			req.Header.Set("Authorization", field)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	base := srv.URL + "/?"
	if err := send(base+strings.Repeat("a", maxOutboundURI-len(base)), ""); err != nil {
		t.Fatalf("a URI at the ceiling was refused: %v", err)
	}
	if arrived.Load() != 1 {
		t.Fatalf("%d requests arrived, want the one", arrived.Load())
	}
	if err := send(base+strings.Repeat("a", maxOutboundURI-len(base)+1), ""); !errors.Is(err, ErrOverlong) {
		t.Errorf("a URI past the ceiling gave %v", err)
	}
	secret := strings.Repeat("s", maxOutboundHeader)
	err := send(srv.URL, secret)
	if !errors.Is(err, ErrOverlong) {
		t.Fatalf("a field past the ceiling gave %v", err)
	}
	if strings.Contains(err.Error(), "sss") {
		t.Errorf("the error repeats the field's value: %v", err)
	}
	if arrived.Load() != 1 {
		t.Errorf("%d requests arrived: something too long was sent", arrived.Load())
	}
}

// Every way of getting a client here carries it, or the one built next does not.
func TestEveryTransportRefusesTheOverlong(t *testing.T) {
	under := func(c *http.Client) *http.Transport {
		tr, ok := Underneath(c.Transport)
		if !ok {
			t.Fatalf("no transport under %T", c.Transport)
		}
		return tr
	}
	for name, tr := range map[string]*http.Transport{
		"Transport":                Transport(),
		"TransportAllowingPrivate": TransportAllowingPrivate(),
		"Client":                   under(Client(time.Second)),
		"ClientTrusting":           under(ClientTrusting(time.Second, nil)),
	} {
		if tr.Proxy == nil {
			t.Errorf("%s has no ceiling", name)
			continue
		}
		req := httptest.NewRequest(http.MethodGet, "https://x.test/"+strings.Repeat("a", maxOutboundURI), nil)
		if _, err := tr.Proxy(req); !errors.Is(err, ErrOverlong) {
			t.Errorf("%s let an overlong URI through: %v", name, err)
		}
	}
}
