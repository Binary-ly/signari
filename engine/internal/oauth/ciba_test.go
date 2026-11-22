package oauth

import "testing"

// §7.1's binding_message, both directions.
//
// The parameter exists so a person can compare what their phone shows against
// what the consumption device shows. That makes both halves security-relevant:
// a character that can restructure or disguise the message defeats it, and a
// validator that rejects ordinary sentences means nobody can use it at all.
func TestTheBindingMessageRejectsWhatCanDisguiseItAndAcceptsWhatPeopleWrite(t *testing.T) {
	// Every one of these was ACCEPTED by the enumerated deny-list this replaced,
	// including members of the two categories that list claimed to cover.
	hostile := map[string]string{
		"U+2028 line separator":         "Approve\U00002028Cancel to continue",
		"U+2029 paragraph separator":    "Approve\U00002029Cancel to continue",
		"U+200E left-to-right mark":     "Send \U0000200E100 GBP",
		"U+200F right-to-left mark":     "Send \U0000200F100 GBP",
		"U+200B zero width space":       "Transfer\U0000200B 4000",
		"U+00AD soft hyphen":            "Trans\U000000ADfer 4000",
		"U+FFF9 interlinear":            "Pay \U0000FFF9hidden\U0000FFFB 5",
		"U+202E right-to-left override": "Send \U0000202E0004 GBP",
		"U+2066 first strong isolate":   "Send \U000020664000 GBP",
		"a bare newline":                "Approve\nCancel",
		"a NUL":                         "Approve\x00Cancel",
		"a non-ASCII space (NBSP)":      "Transfer\U000000A04000",
	}
	for name, s := range hostile {
		if err := validBindingMessage(s); err == nil {
			t.Errorf("%s was accepted; it can make the approval prompt read as "+
				"something other than what it says", name)
		}
	}

	fine := map[string]string{
		"an ordinary sentence": "Transfer 4000 GBP to Bob",
		"a currency symbol":    "Transfer £4,000 to Bob",
		"Arabic":               "تحويل 4000 جنيه إسترليني",
		"Japanese":             "4000ポンドを送金",
		"an emoji":             "Transfer 4000 GBP 💷",
		"punctuation":          "Did you just try to move £4,000? (ref: 7QF-2K9)",
	}
	for name, s := range fine {
		if err := validBindingMessage(s); err != nil {
			t.Errorf("%s was refused, which makes binding_message unusable for the "+
				"thing it exists for: %v", name, err)
		}
	}
}
