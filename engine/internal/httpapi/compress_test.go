package httpapi

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTakesGzipReadsWhatWasSaid(t *testing.T) {
	for header, want := range map[string]bool{
		"":                       false,
		"gzip":                   true,
		"GZIP":                   true,
		"deflate, gzip;q=0.5":    true,
		"br, gzip ; q=1.0, zstd": true,
		"gzip;q=0":               false,
		"gzip;q=0.0":             false,
		"identity":               false,
		"*":                      false,
		"gzipped":                false,
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept-Encoding", header)
		if got := takesGzip(r); got != want {
			t.Errorf("%q: %v", header, got)
		}
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	out, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The same document either way, a different ETag for each, and a validator that
// answers for the form it names: a client that cannot read gzip is not told that what
// it holds is good by a cache holding the compressed bytes.
func TestDiscoveryIsCompressedForWhoeverAsks(t *testing.T) {
	f := newTokenFixture(t)
	h := f.srv.Routes()
	get := func(accept, match string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		if accept != "" {
			r.Header.Set("Accept-Encoding", accept)
		}
		if match != "" {
			r.Header.Set("If-None-Match", match)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	plain, zipped := get("", ""), get("gzip", "")
	if plain.Code != http.StatusOK || zipped.Code != http.StatusOK {
		t.Fatalf("%d, %d", plain.Code, zipped.Code)
	}
	if plain.Header().Get("Content-Encoding") != "" {
		t.Error("compressed for a client that did not ask")
	}
	if zipped.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("not compressed: %v", zipped.Header())
	}
	if !bytes.Equal(gunzip(t, zipped.Body.Bytes()), plain.Body.Bytes()) {
		t.Error("the compressed document is another document")
	}
	if zipped.Body.Len() >= plain.Body.Len() {
		t.Errorf("%d bytes from %d", zipped.Body.Len(), plain.Body.Len())
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{"plain": plain, "compressed": zipped} {
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: no Vary, so a cache would serve either to anybody", name)
		}
	}
	plainTag, zippedTag := plain.Header().Get("ETag"), zipped.Header().Get("ETag")
	if plainTag == "" || plainTag == zippedTag {
		t.Fatalf("ETags %q and %q", plainTag, zippedTag)
	}
	if rec := get("gzip", zippedTag); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("revalidating the compressed form: %d", rec.Code)
	}
	if rec := get("", plainTag); rec.Code != http.StatusNotModified {
		t.Errorf("revalidating the plain form: %d", rec.Code)
	}
	if rec := get("", zippedTag); rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("a client that cannot read it, holding the compressed tag: %d %q", rec.Code, rec.Header().Get("Content-Encoding"))
	}
}

// A short document is left alone, a long one compressed once, and a new one again.
func TestADocumentIsCompressedOnceAndOnlyIfWorthIt(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	var memo gzipMemo
	short, tag := negotiate(httptest.NewRecorder(), r, &memo, []byte("short"), `"a"`)
	if string(short) != "short" || tag != `"a"` {
		t.Errorf("%q %q", short, tag)
	}
	long := bytes.Repeat([]byte("key "), compressFrom)
	first, _ := negotiate(httptest.NewRecorder(), r, &memo, long, `"a"`)
	second, _ := negotiate(httptest.NewRecorder(), r, &memo, long, `"a"`)
	if len(first) == 0 || &first[0] != &second[0] {
		t.Error("compressed again for the same ETag")
	}
	changed := bytes.Repeat([]byte("new "), compressFrom)
	third, _ := negotiate(httptest.NewRecorder(), r, &memo, changed, `"b"`)
	if !bytes.Equal(gunzip(t, third), changed) {
		t.Error("the old document was served for a new ETag")
	}
}

// Over a real socket with no TLS, as a proxy would speak it.
func TestTheListenerSpeaksH2CWhenAsked(t *testing.T) {
	proto := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { proto <- r.Proto }))
	AllowH2C(srv.Config)
	srv.Start()
	defer srv.Close()

	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := <-proto; got != "HTTP/2.0" {
		t.Errorf("the server saw %s", got)
	}

	// And HTTP/1.1 still, which is what most proxies and every health check speak.
	plain, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	if got := <-proto; got != "HTTP/1.1" {
		t.Errorf("the server saw %s", got)
	}

	// The other way in is the one a browser can be made to ask for through a proxy
	// that passes the header on, and it is not there.
	upgrade, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	upgrade.Header.Set("Connection", "Upgrade, HTTP2-Settings")
	upgrade.Header.Set("Upgrade", "h2c")
	upgrade.Header.Set("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")
	asked, err := (&http.Client{Transport: &http.Transport{}}).Do(upgrade)
	if err != nil {
		t.Fatal(err)
	}
	_ = asked.Body.Close()
	if asked.StatusCode == http.StatusSwitchingProtocols {
		t.Error("the listener took the upgrade")
	}
	if got := <-proto; got != "HTTP/1.1" {
		t.Errorf("the server saw %s", got)
	}
}

// Off, a client speaking HTTP/2 in the clear finds nobody who understands it.
func TestTheListenerDoesNotSpeakH2CUnlessAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	defer transport.CloseIdleConnections()
	if resp, err := (&http.Client{Transport: transport}).Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		if resp.Proto == "HTTP/2.0" {
			t.Error("HTTP/2 in the clear was served with nothing asking for it")
		}
	}
}
