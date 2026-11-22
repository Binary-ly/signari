package proxyproto

import (
	"bytes"
	"testing"
)

// A PROXY v2 header is the first bytes a trusted balancer sends, and the first bytes
// anybody who reaches the listener directly can send. Reading ends in an address, nil,
// or an error, and never reads past the header it reports: the bytes after it are the
// connection's.
func FuzzRead(f *testing.F) {
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	f.Add(append(append([]byte{}, sig...), 0x21, 0x11, 0, 12, 10, 0, 0, 1, 10, 0, 0, 2, 0x1f, 0x90, 0x01, 0xbb))
	f.Add(append(append([]byte{}, sig...), 0x20, 0x00, 0, 0))
	f.Add(append(append([]byte{}, sig...), 0x21, 0x21, 0, 36))
	f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bytes.NewReader(raw)
		if _, err := Read(r); err != nil {
			return
		}
		if read := len(raw) - r.Len(); read < 16 || read > len(raw) {
			t.Fatalf("a header of %d bytes read from %d", read, len(raw))
		}
	})
}
