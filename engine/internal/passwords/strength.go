package passwords

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Estimating how many guesses a password would survive.
//
// # Why length is not enough, and why composition rules are worse
//
// `Password123!` is twelve characters and satisfies every composition rule ever
// written. `aaaaaaaaaaaa` is twelve characters. `qwertyuiop12` is twelve
// characters. A length check passes all three, and an attacker's first thousand
// guesses contain all three.
//
// So this counts GUESSES rather than characters: how many attempts a password
// would survive against somebody who knows how people actually build them.
// That is the idea zxcvbn introduced and it is the right one.
//
// # What this does that zxcvbn does not
//
// zxcvbn scores against a static frequency list compiled in 2012 and never
// consults a breach corpus -- so a password that is genuinely in a hundred
// dumps scores well as long as it is not in the built-in dictionary. Policy
// runs both: the estimate here catches STRUCTURE (a keyboard walk, a date, a
// repeated word) and the corpus catches HISTORY. Neither finds what the other
// does.
//
// # The dictionary, and why it is small
//
// The first version of this shipped no word list at all, on the reasoning that
// the breach corpus covers it. Its own test immediately disproved that:
// `p@ssw0rd` and `Password123!` both scored 4/4, because no STRUCTURAL pattern
// matches an English word. The corpus would have caught them -- but the corpus
// is off by default and needs a network, so the default configuration was
// rating the two most-guessed passwords in the world as unbreakable.
//
// So there is a word list. It is a few hundred entries rather than zxcvbn's
// thirty thousand, because the curve is steep: the top few hundred bases cover
// the overwhelming majority of human-chosen passwords, and everything past that
// is better served by the breach corpus, which is bigger, current, and already
// consulted. Structure detection and a small list catch what a corpus cannot --
// a password CONSTRUCTED from a cheap pattern that has never appeared in a dump.

// Strength is an estimate of how hard a password is to guess.
type Strength struct {
	// Guesses is the estimated number of attempts to find it. Not a
	// probability and not a percentage: the only honest unit here is "how many
	// tries", because that is what an attacker spends.
	Guesses float64
	// Score is 0..4, the scale people already know from zxcvbn.
	Score int
	// Pattern names the cheapest structure found, for the message shown.
	Pattern string
}

// Guess-count thresholds for each score. The boundaries are zxcvbn's, so a
// deployment migrating from it keeps the same meaning for "score 3".
var scoreAt = []float64{1e3, 1e6, 1e8, 1e10}

// keyboard rows, for detecting walks like `qwerty` or `asdfgh`.
//
// Only the layouts worth the bytes. A walk on an unusual layout is still caught
// by the sequence and repetition checks; what is bought here is the common case.
var keyboards = []string{
	"`1234567890-=",
	"qwertyuiop[]\\",
	"asdfghjkl;'",
	"zxcvbnm,./",
	// AZERTY and QWERTZ differ enough in the top row to be worth listing.
	"azertyuiop",
	"qwertzuiop",
}

// Estimate scores a password.
//
// `identity` is the person's username or email, when known: a password built
// from it is cheap to guess for anyone who knows who they are, and no amount of
// entropy in the rest of the string fixes that.
func Estimate(password, identity string) Strength {
	if password == "" {
		return Strength{Guesses: 1, Score: 0, Pattern: "empty"}
	}
	rs := []rune(password)
	lower := strings.ToLower(password)

	// The cheapest structure wins. An attacker does not have to find the
	// expensive interpretation of a password, only the cheap one -- so taking
	// the MINIMUM across patterns is the only safe reading.
	best := math.Inf(1)
	pattern := ""
	consider := func(guesses float64, name string) {
		if guesses < best {
			best, pattern = guesses, name
		}
	}

	// Baseline: brute force over the character classes actually used.
	consider(bruteForce(rs), "")

	if n := repeatedUnit(lower); n > 0 {
		// `abcabcabc` costs roughly what `abc` costs, plus the repeat count.
		consider(bruteForce([]rune(lower[:n]))*float64(len(lower)/n), "a repeated block")
	}
	if runLength(lower) >= 3 {
		// `aaaaaa`, `111111`. Cost is the alphabet times the length, not the
		// alphabet TO the length.
		consider(float64(len(rs))*26, "one character repeated")
	}
	if sequenceRun(lower) >= 4 {
		// `abcdef`, `123456`, `zyxwvu`.
		consider(float64(len(rs))*100, "a sequence like abcdef or 123456")
	}
	if keyboardWalk(lower) >= 4 {
		consider(float64(len(rs))*200, "a keyboard pattern like qwerty")
	}
	if looksLikeDate(lower) {
		// A date has at most a few hundred thousand plausible values.
		consider(3.6e5, "a date")
	}
	if identity != "" {
		local := identity
		if at := strings.IndexByte(local, '@'); at > 0 {
			local = local[:at]
		}
		if len(local) >= 3 && strings.Contains(lower, strings.ToLower(local)) {
			// Free to guess for anyone who knows the person.
			consider(100, "your own name or address")
		}
	}
	if only(rs, unicode.IsDigit) {
		consider(math.Pow(10, float64(len(rs))), "digits only")
	}

	// A common word with decoration is the commonest human password there is.
	// Stripped of trailing digits and symbols and un-leeted, `P@ssw0rd123!`
	// is `password` -- and the cost is the list position, times the cheap
	// decorations, not the alphabet raised to twelve.
	if base, deco := strip(lower); base != "" {
		if rank, ok := commonWords[deleet(base)]; ok {
			consider(float64(rank)*deco, "a very common password with additions")
		}
	}

	// Leetspeak is not strength. `p@ssw0rd` is `password` with three
	// substitutions -- a factor of eight, not a new password.
	if de := deleet(lower); de != lower {
		if runLength(de) >= 3 || sequenceRun(de) >= 4 || keyboardWalk(de) >= 4 {
			consider(best/8, "a common word with letters swapped for symbols")
		}
	}

	s := Strength{Guesses: best, Pattern: pattern}
	for _, t := range scoreAt {
		if best >= t {
			s.Score++
		}
	}
	return s
}

// bruteForce is the cost of trying every string of this length over the
// character classes present.
func bruteForce(rs []rune) float64 {
	var lowerC, upperC, digit, symbol, other bool
	for _, r := range rs {
		switch {
		case unicode.IsLower(r) && r < 128:
			lowerC = true
		case unicode.IsUpper(r) && r < 128:
			upperC = true
		case unicode.IsDigit(r) && r < 128:
			digit = true
		case r < 128:
			symbol = true
		default:
			other = true
		}
	}
	alphabet := 0
	if lowerC {
		alphabet += 26
	}
	if upperC {
		alphabet += 26
	}
	if digit {
		alphabet += 10
	}
	if symbol {
		alphabet += 33
	}
	if other {
		// Non-ASCII. Counted conservatively rather than optimistically: a
		// passphrase in another script is not automatically strong, and
		// crediting it with the whole of Unicode would make one short word
		// score as unbreakable.
		alphabet += 100
	}
	if alphabet == 0 {
		return 1
	}
	// Capped, because float64 overflows to +Inf around 1e308 and an infinite
	// score compares strangely against every threshold.
	e := float64(len(rs)) * math.Log2(float64(alphabet))
	if e > 200 {
		e = 200
	}
	return math.Pow(2, e)
}

// runLength is the longest run of one repeated character.
func runLength(s string) int {
	rs := []rune(s)
	best, cur := 0, 1
	for i := 1; i < len(rs); i++ {
		if rs[i] == rs[i-1] {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best = cur
		}
	}
	if len(rs) == 1 {
		return 1
	}
	return best
}

// sequenceRun is the longest ascending or descending run by code point.
func sequenceRun(s string) int {
	rs := []rune(s)
	if len(rs) < 2 {
		return 0
	}
	best, cur, dir := 1, 1, 0
	for i := 1; i < len(rs); i++ {
		d := int(rs[i]) - int(rs[i-1])
		if d != 1 && d != -1 {
			cur, dir = 1, 0
			continue
		}
		if d == dir {
			cur++
		} else {
			cur, dir = 2, d
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

// keyboardWalk is the longest run of adjacent keys on a common layout.
func keyboardWalk(s string) int {
	rs := []rune(s)
	if len(rs) < 2 {
		return 0
	}
	best, cur := 1, 1
	for i := 1; i < len(rs); i++ {
		if adjacentKeys(rs[i-1], rs[i]) {
			cur++
		} else {
			cur = 1
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func adjacentKeys(a, b rune) bool {
	for _, row := range keyboards {
		ia := strings.IndexRune(row, a)
		ib := strings.IndexRune(row, b)
		if ia >= 0 && ib >= 0 && (ia-ib == 1 || ib-ia == 1) {
			return true
		}
	}
	return false
}

// repeatedUnit returns the length of the smallest block the string repeats, or 0.
func repeatedUnit(s string) int {
	n := len(s)
	if n < 4 {
		return 0
	}
	for unit := 1; unit <= n/2; unit++ {
		if n%unit != 0 {
			continue
		}
		ok := true
		for i := unit; i < n; i++ {
			if s[i] != s[i-unit] {
				ok = false
				break
			}
		}
		if ok {
			return unit
		}
	}
	return 0
}

// looksLikeDate reports whether the string is mostly a date.
func looksLikeDate(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	// Mostly digits, and short enough to be a date rather than a long number.
	if digits < 4 || digits > 8 || float64(digits) < float64(len([]rune(s)))*0.6 {
		return false
	}
	// A four-digit run in a plausible year range is the strongest signal.
	for i := 0; i+4 <= len(s); i++ {
		chunk := s[i : i+4]
		if allDigits(chunk) {
			y := atoi(chunk)
			if y >= 1900 && y <= 2100 {
				return true
			}
		}
	}
	return digits >= 6
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// deleet undoes the usual substitutions, so `p@ssw0rd` is scored as `password`.
func deleet(s string) string {
	r := strings.NewReplacer(
		"@", "a", "4", "a", "3", "e", "1", "l", "!", "i", "0", "o",
		"$", "s", "5", "s", "7", "t", "+", "t", "8", "b")
	return r.Replace(s)
}

func only(rs []rune, pred func(rune) bool) bool {
	for _, r := range rs {
		if !pred(r) {
			return false
		}
	}
	return len(rs) > 0
}

// Explain turns a weak estimate into something worth reading.
//
// It names the STRUCTURE that made it cheap, because "your password is weak" is
// advice nobody can act on, and "that is a keyboard pattern" is advice anybody
// can.
func (s Strength) Explain() string {
	base := "that password would be guessed quickly"
	if s.Pattern != "" {
		base += " -- it is built around " + s.Pattern
	}
	return base + ". Several unrelated words are far harder to guess than a " +
		"short one with symbols in it, and much easier to remember"
}

// String is for logs and the CLI.
func (s Strength) String() string {
	return fmt.Sprintf("score %d/4 (~%.0e guesses)", s.Score, s.Guesses)
}

// strip removes leading/trailing digits and symbols, returning the alphabetic
// core and a multiplier for how much the decoration costs an attacker.
//
// `P@ssw0rd123!` -> ("p@ssw0rd", small): appending a year or `123!` is the
// first thing a cracking rule tries, so it multiplies the cost by a few
// thousand at most -- not by the alphabet raised to the length.
func strip(s string) (base string, decoration float64) {
	i, j := 0, len(s)
	for i < j && !isAlpha(s[i]) {
		i++
	}
	for j > i && !isAlpha(s[j-1]) {
		j--
	}
	if j-i < 3 {
		return "", 1
	}
	// Each stripped character is one an off-the-shelf rule appends. 100 per
	// character is generous to the password, which is the safe direction.
	n := (i) + (len(s) - j)
	deco := math.Pow(100, float64(n))
	if deco < 1 {
		deco = 1
	}
	if deco > 1e6 {
		deco = 1e6 // a long suffix is still only a suffix
	}
	return s[i:j], deco
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// commonWords maps a base word to its approximate rank in real-world password
// dumps. The rank IS the guess cost: a word at position 12 is found on the
// twelfth guess.
//
// Ordered by frequency across published breach analyses, truncated where the
// curve flattens. Deliberately not thirty thousand words -- see the file
// comment.
var commonWords = buildCommonWords()

func buildCommonWords() map[string]int {
	list := []string{
		"password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein",
		"dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine", "master",
		"welcome", "shadow", "ashley", "football", "jesus", "michael", "ninja",
		"mustang", "access", "batman", "superman", "starwars", "hello", "freedom",
		"whatever", "qazwsx", "princess", "login", "admin", "root", "guest", "user",
		"test", "changeme", "secret", "summer", "winter", "spring", "autumn",
		"january", "february", "march", "april", "june", "july", "august",
		"september", "october", "november", "december", "monday", "friday",
		"soccer", "hockey", "killer", "george", "sexy", "andrew", "charlie",
		"superman", "asshole", "fuckyou", "dallas", "jessica", "panties", "pepper",
		"1234", "696969", "harley", "ranger", "buster", "thomas", "tigger", "robert",
		"soccer", "batman", "hunter", "fuckme", "computer", "amanda", "wizard",
		"xxxxxxxx", "money", "phoenix", "mickey", "bailey", "knight", "iceman",
		"tigers", "purple", "andrea", "horny", "dakota", "aaaaaa", "player",
		"sunshine", "morgan", "starwars", "boomer", "cowboys", "edward", "charles",
		"girls", "booboo", "coffee", "xxxxxx", "bulldog", "ncc1701", "rabbit",
		"peanut", "john", "johnny", "gandalf", "spanky", "winter", "brandy",
		"compaq", "carlos", "tennis", "james", "mike", "brandon", "fender",
		"anthony", "blowme", "ferrari", "cookie", "chicken", "maverick", "chicago",
		"joseph", "diablo", "sexsex", "hardcore", "666666", "willie", "welcome",
		"chris", "panther", "yamaha", "justin", "banana", "driver", "marine",
		"angels", "fishing", "david", "maggie", "legend", "jordan", "toyota",
		"orange", "please", "guitar", "happy", "flower", "cheese", "internet",
		"service", "canada", "hello123", "ranger", "hammer", "silver", "222222",
		"88888888", "anthony", "justin", "love", "loveme", "qwerty123", "qwertyuiop",
		"asdfgh", "zxcvbn", "1qaz2wsx", "abcdef", "letmein123", "passw0rd",
		"password1", "password123", "admin123", "welcome1", "companyname",
		"linkedin", "facebook", "google", "twitter", "amazon", "netflix", "spotify",
		"microsoft", "windows", "apple", "samsung", "android", "iphone",
	}
	m := make(map[string]int, len(list))
	for i, w := range list {
		if _, seen := m[w]; !seen {
			// Rank starts at 1: the first word costs one guess.
			m[w] = i + 1
		}
	}
	return m
}
