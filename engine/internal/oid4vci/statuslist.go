package oid4vci

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Token Status List, draft-ietf-oauth-status-list-21 (specs/token-status-list.txt): how a
// credential that has left is taken back. Each one carries a place in a list, and the list
// is a signed token anybody can fetch, so asking about one credential tells the issuer
// only that somebody asked about one of a great many.

const (
	// StatusListEntries is how many places one list has, one bit each. §13.4 recommends
	// a size divisible by eight; this is 16 KiB before compression.
	StatusListEntries = 1 << 17

	// StatusListFilledAt is when a list stops taking more. Half of it is never handed
	// out: §12.5.1 recommends decoy entries, and random places stay quick to find.
	StatusListFilledAt = StatusListEntries / 2

	// StatusTokenMedia is §8.2's content type, and the only one here: SD-JWT VC holds a
	// credential of its format to a Status List Token "in JWT format".
	StatusTokenMedia = "application/statuslist+jwt"

	statusTokenType = "statuslist+jwt"

	// StatusTokenTTL is §5.1's ttl: how long a verifier may keep a list, so the longest
	// a revocation takes to reach one that follows it. The token is made per request, so
	// nothing here is out of date for longer than a verifier chooses.
	StatusTokenTTL = 5 * time.Minute

	// statusTokenValidity is §5.1's exp, past which nobody may rely on the list.
	statusTokenValidity = time.Hour
)

// StatusPlace is the place of one credential, its §6.2 `status_list`.
type StatusPlace struct {
	Index int
	URI   string
}

func (p StatusPlace) claim() map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": p.Index, "uri": p.URI}}
}

// EncodeStatusList is §4.1 at one bit each: the statuses packed from the least significant
// bit, compressed with DEFLATE in the ZLIB format, then §4.2's base64url.
func EncodeStatusList(entries int, invalid []int) (string, error) {
	statuses := make([]byte, entries/8)
	for _, index := range invalid {
		if index < 0 || index >= entries {
			return "", fmt.Errorf("status index %d is outside a list of %d", index, entries)
		}
		statuses[index/8] |= 1 << (index % 8)
	}
	var compressed bytes.Buffer
	z, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := z.Write(statuses); err != nil {
		return "", err
	}
	if err := z.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(compressed.Bytes()), nil
}

// StatusListToken signs the §5.1 token of a list, sub being the URI its credentials carry.
func StatusListToken(uri, issuer string, invalid []int, now time.Time,
	sign func(payload []byte, typ string) (string, error)) (string, error) {

	list, err := EncodeStatusList(StatusListEntries, invalid)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": uri, "iat": now.Unix(), "exp": now.Add(statusTokenValidity).Unix(),
		"ttl": int(StatusTokenTTL.Seconds()), "status_list": map[string]any{"bits": 1, "lst": list},
	})
	if err != nil {
		return "", err
	}
	return sign(payload, statusTokenType)
}
