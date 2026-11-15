package httpapi

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// gzip for the few long public documents (E.22): discovery, the key set and SAML
// metadata, which are fetched by every relying party. Nothing else: a page with a
// secret and a guess in the same response is what compression must not touch, and
// these have neither.

// compressFrom is the length below which compressing costs more than it saves.
const compressFrom = 1024

// gzipped is a document's compressed form, as of its ETag.
type gzipped struct {
	etag string
	body []byte
}

// gzipMemo holds the last one, so that a document fetched thousands of times is
// compressed once. Replaced whole, and only ever by the form of a newer document.
type gzipMemo struct{ last atomic.Pointer[gzipped] }

func (m *gzipMemo) of(etag string, body []byte) ([]byte, bool) {
	if g := m.last.Load(); g != nil && g.etag == etag {
		return g.body, true
	}
	out, ok := gzipBytes(body)
	if !ok {
		return nil, false
	}
	m.last.Store(&gzipped{etag: etag, body: out})
	return out, true
}

func gzipBytes(body []byte) ([]byte, bool) {
	var buf bytes.Buffer
	z, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, false
	}
	if _, err := z.Write(body); err != nil {
		return nil, false
	}
	if err := z.Close(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// takesGzip reads Accept-Encoding for gzip. A weight of zero is a refusal, and an
// asterisk is not taken for it: a client that has not named gzip gets what it has
// always got.
func takesGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		if q, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if weight, err := strconv.ParseFloat(q, 64); err != nil || weight == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// negotiate chooses the form of a public document a request is answered with, and
// says whether that form is gzip. The form has an ETag of its own: a content coding
// is a characteristic of the representation (RFC 9110 §8.4), so one ETag on both
// would have a cache revalidate the compressed bytes for a client that cannot read
// them.
//
// It does not set Content-Encoding itself. The caller does, on the response that
// carries this body and on no other: when this set it, every answer the handler gave
// afterwards inherited it, and the key set's 429 sent a plain JSON refusal labelled
// gzip, which no client could read (0.110), at the moment after a rotation when
// relying parties refetch at once and the refusal is the answer most of them get.
func negotiate(w http.ResponseWriter, r *http.Request, memo *gzipMemo, body []byte, etag string) ([]byte, string, bool) {
	w.Header().Add("Vary", "Accept-Encoding")
	if len(body) < compressFrom || !takesGzip(r) {
		return body, etag, false
	}
	var out []byte
	var ok bool
	if memo != nil {
		out, ok = memo.of(etag, body)
	} else {
		out, ok = gzipBytes(body)
	}
	if !ok {
		return body, etag, false
	}
	if tag, cut := strings.CutSuffix(etag, `"`); cut {
		etag = tag + `-gzip"`
	}
	return out, etag, true
}

// encodedAs marks the response about to carry a negotiated body with its coding.
func encodedAs(w http.ResponseWriter, gzipped bool) {
	if gzipped {
		w.Header().Set("Content-Encoding", "gzip")
	}
}
