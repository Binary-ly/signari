package oauth

import "strings"

// ErrorText makes a sentence fit to send as error_description. RFC 6749 says it in the
// same words of an authorization error, an implicit one and a token error
// (specs/rfc6749.txt:1555, 2044, 2538): "Values for the "error_description" parameter MUST
// NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E." So no double quote,
// no backslash, nothing but printable ASCII, and RFC 6750 §3 puts the same set on the
// challenge. Applied where the field is written, so a sentence built anywhere is safe.
func ErrorText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"':
			return '\''
		case r == '\\':
			return '/'
		case r < 0x20 || r > 0x7e:
			return ' '
		}
		return r
	}, s)
}
