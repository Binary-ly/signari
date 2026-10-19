// Package hmacsig is the one signature this engine puts on a request it sends
// to a service the operator runs: event deliveries and extension provider
// calls.
//
//	Signari-Signature: t=1786972759,v1=<hex hmac-sha256>
//
// The MAC covers `t.body` -- the timestamp AND the body, joined -- not the body
// alone. Signing only the body means a captured request can be replayed
// forever, and the receiver has no way to tell a live one from last month's.
// With the timestamp inside the MAC, changing it invalidates the signature, so
// a receiver can refuse anything outside a few minutes and mean it.
//
// One package because two copies of one MAC is one implementation and one bug,
// and because the provider package cannot import outbox, which reaches it
// through store.
package hmacsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Header carries the MAC.
const Header = "Signari-Signature"

// Sign returns the header value for a body at a time.
func Sign(secret string, at time.Time, body []byte) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	// t.body -- the separator matters. Without it, (t=1, body="23") and
	// (t=12, body="3") produce the same MAC, and a signature that is ambiguous
	// about what it signed is not a signature.
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
