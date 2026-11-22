package store

import (
	"errors"
	"strings"
	"testing"
)

// What goes in a From line is one address, written plainly, and a name beside it.
// Either could reach a message's headers, and a display name inside the address
// is a second place to say who a message is from.
func TestAMailSenderIsOnePlainAddress(t *testing.T) {
	long := strings.Repeat("a", maxMailSenderName)
	for _, c := range []struct {
		name, from, says string
		ok               bool
	}{
		{"none", "", "", true},
		{"an address", "id@acme.example", "", true},
		{"an address and a name", "id@acme.example", "Acme Identity", true},
		{"a name not in ASCII", "id@acme.example", "هوية أكمي", true},
		{"the longest name", "id@acme.example", long, true},
		{"a name too long", "id@acme.example", long + "a", false},
		{"a name with no address", "", "Acme", false},
		{"a name inside the address", "Acme <id@acme.example>", "", false},
		{"a line break in the name", "id@acme.example", "Acme\r\nBcc: x@evil.test", false},
		{"a tab in the name", "id@acme.example", "Acme\tIdentity", false},
		{"a line break in the address", "id@acme.example\r\nBcc: x@evil.test", "", false},
		{"two addresses", "a@acme.example,b@acme.example", "", false},
		{"no domain", "id@", "", false},
		{"nothing like one", "acme", "", false},
	} {
		err := checkMailSender(c.from, c.says)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrMailSender) {
			t.Errorf("%s: answered %v", c.name, err)
		}
	}
}
