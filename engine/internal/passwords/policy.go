package passwords

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// One gate every new password passes through.
//
// # Why it is one function
//
// A password can be set at sign-up, at recovery, by an administrator, and from
// the command line. Four checks in four places means one of them is eventually
// weaker than the others, and the weak one is the one an attacker uses. So the
// rules live here and each of those paths calls this.
//
// # What is deliberately NOT here
//
// Composition rules — "one uppercase, one digit, one symbol". NIST SP 800-63B
// advises against them: they push people towards `Password1!`, which is in every
// breach corpus, and away from long passphrases, which are not. Length and a
// breach check do the work those rules pretend to do.
//
// What IS checked besides length is context: a password containing the person's
// own email address is guessable by anyone who knows who they are, and no
// composition rule catches it.

// Policy is a deployment's password rules.
type Policy struct {
	// MinLength is the floor, and the number changed under us.
	//
	// NIST SP 800-63B **revision 4** §3.1.1.2:
	//
	//	"Verifiers and CSPs SHALL require passwords that are used as a
	//	single-factor authentication mechanism to be a minimum of 15 characters
	//	in length. Verifiers and CSPs MAY allow passwords that are only used as
	//	part of multi-factor authentication processes to be shorter but SHALL
	//	require them to be a minimum of eight characters in length."
	//
	// This said 8, citing SP 800-63B -- which was correct for revision 3 and is
	// the more dangerous kind of stale: an accurate citation of a superseded
	// document reads like diligence, so nobody re-checks it.
	//
	// 15 is the default because this policy does not know whether a second
	// factor will be present. A deployment that enforces MFA for every account
	// may lower it to 8; one that does not, may not. Getting that wrong in the
	// permissive direction is a single-factor password below the floor, so the
	// default is the number that is safe without knowing.
	MinLength int
	// MaxLength guards the hasher rather than the password. Argon2 over a
	// megabyte of input is a denial of service with a text box in front of it.
	MaxLength int

	// Breach, when set, refuses passwords found in a breach corpus.
	Breach *BreachChecker
	// BreachRequired decides what an unreachable corpus means.
	//
	// False (the default) lets the password through and expects the caller to
	// log it: a third party's outage should not stop an entire company changing
	// passwords, and this check is defence in depth rather than the only control.
	//
	// True refuses instead, for deployments that must be able to say the check
	// ran every time. Both are defensible; what is not defensible is choosing
	// silently, so this is a field rather than a default nobody sees.
	BreachRequired bool

	// HistoryDepth refuses reuse of this many previous passwords. 0 disables it.
	HistoryDepth int

	// MinScore refuses passwords below this guess-strength score (0..4).
	//
	// 0 disables it. This is the check that catches `Password123!` -- twelve
	// characters, every composition rule satisfied, and in an attacker's first
	// thousand guesses. Length cannot see it and composition rules encourage it.
	MinScore int

	// RecheckEvery re-consults the corpus at sign-in, at most this often per
	// credential. 0 disables it.
	//
	// This is the part the alternatives do not have. A breach corpus only grows,
	// so checking once when a password is chosen means the control stops working
	// the day after it ran -- and sign-in is the only moment the plaintext exists
	// to check again. Bounded per credential so a third party is never on the
	// critical path of every login.
	RecheckEvery time.Duration
}

// MinLengthSingleFactor and MinLengthWithMFA are SP 800-63B-4 §3.1.1.2's two
// floors. The second applies ONLY to a password that is never used on its own.
const (
	MinLengthSingleFactor = 15
	MinLengthWithMFA      = 8
)

// DefaultPolicy is what a deployment gets without configuring anything.
func DefaultPolicy() Policy {
	return Policy{MinLength: MinLengthSingleFactor, MaxLength: 1024}
}

// Result explains an outcome to the caller as well as to the user.
type Result struct {
	// BreachCheckRan is false when the corpus could not be consulted. The caller
	// logs this; a control that silently stopped running is worse than one that
	// was never configured.
	BreachCheckRan bool
	// Score is the guess-strength estimate, when one was made.
	Score int
}

// Check validates a candidate password.
//
// `identity` is the person's email or username, and `previous` are their recent
// hashes, most recent first. Both may be empty.
func (p Policy) Check(ctx context.Context, candidate, identity string,
	previous []string, hasher *Hasher) (Result, error) {

	var res Result

	min := p.MinLength
	if min <= 0 {
		min = MinLengthSingleFactor
	}
	max := p.MaxLength
	if max <= 0 {
		max = 1024
	}

	// Normalised to NFC before anything looks at it.
	//
	// SP 800-63B-4 §3.1.1.2: "If Unicode characters are accepted in passwords,
	// the verifier SHOULD apply the normalization process for stabilized strings
	// using the Normalization Form Canonical Composition (NFC) normalization...
	// This process is applied before hashing the byte string that represents the
	// password."
	//
	// The failure it prevents is not theoretical. "é" can be one code point or
	// two, and which one a keyboard produces depends on the platform. Without
	// this, a password set on a Mac and typed on Windows is a different byte
	// string and simply does not verify -- intermittently, for a minority of
	// users, with no error anyone can act on.
	//
	// ASCII is unaffected: NFC is the identity function on it, so the
	// overwhelming majority of passwords hash to exactly what they did before.
	//
	// The hashing itself normalises too, in Hasher.Hash and Hasher.Verify --
	// that is where the SHOULD is actually satisfied, because those are the only
	// two places a password becomes bytes. This call is so that the LENGTH check
	// below measures the same string that will be hashed: a decomposed "é" is
	// two code points before normalisation and one after, so checking the length
	// of the un-normalised form would measure a different password.
	candidate = Normalize(candidate)

	// Counted in RUNES. len() on a Go string is bytes, so a passphrase in a
	// non-Latin script would be measured as several times its real length and a
	// short one would pass a check it should fail.
	//
	// §3.1.1.2 makes this explicit: "Each Unicode code point SHALL be counted as
	// a single character when evaluating password length."
	n := len([]rune(candidate))
	switch {
	case n < min:
		return res, fmt.Errorf("passwords must be at least %d characters. A "+
			"passphrase of a few unrelated words is easier to remember and far "+
			"harder to guess than a short one with symbols in it", min)
	case n > max:
		return res, fmt.Errorf("that password is longer than %d characters", max)
	}

	if strings.TrimSpace(candidate) == "" {
		return res, fmt.Errorf("that password is only whitespace")
	}

	// Context: a password containing the person's own address or username is
	// guessable by anyone who knows who they are, and no composition rule
	// catches it.
	if identity != "" {
		local := identity
		if at := strings.IndexByte(local, '@'); at > 0 {
			local = local[:at]
		}
		if len(local) >= 4 && strings.Contains(strings.ToLower(candidate),
			strings.ToLower(local)) {
			return res, fmt.Errorf("that password contains your username, which " +
				"makes it guessable by anyone who knows who you are")
		}
	}

	// A single repeated character passes any length rule and is in every corpus.
	if repeatedRun(candidate) {
		return res, fmt.Errorf("that password is one character repeated")
	}

	// Guess strength, BEFORE the network. It costs nothing, it runs the same
	// everywhere, and it catches the structural weakness a corpus lookup would
	// only catch if that exact string had already leaked.
	if p.MinScore > 0 {
		st := Estimate(candidate, identity)
		res.Score = st.Score
		if st.Score < p.MinScore {
			return res, fmt.Errorf("%s", st.Explain())
		}
	}

	// Reuse, before the breach check: it needs no network and a reused password
	// is refused either way.
	if p.HistoryDepth > 0 && hasher != nil {
		limit := p.HistoryDepth
		if limit > len(previous) {
			limit = len(previous)
		}
		for i := 0; i < limit; i++ {
			if _, err := hasher.Verify(ctx, previous[i], candidate); err == nil {
				return res, fmt.Errorf("that is one of your last %d passwords. "+
					"Reusing one undoes the reason for changing it", p.HistoryDepth)
			}
		}
	}

	if p.Breach != nil {
		breached, err := p.Breach.Breached(ctx, candidate)
		switch {
		case err == nil:
			res.BreachCheckRan = true
			if breached {
				// Deliberately not "how many times". A count invites bargaining,
				// and the answer is the same whatever it is.
				return res, fmt.Errorf("that password appears in a known breach, " +
					"so it is already in the lists attackers try first. Choose " +
					"another -- it does not have to be complicated, only unused")
			}
		case p.BreachRequired:
			return res, fmt.Errorf("the breach check could not run and this " +
				"deployment requires it, so the password was not accepted. Try again")
		default:
			// Let it through, and the caller logs that the check did not run.
		}
	}
	return res, nil
}

// repeatedRun reports whether the whole string is one character.
func repeatedRun(s string) bool {
	rs := []rune(s)
	if len(rs) < 2 {
		return true
	}
	first := unicode.ToLower(rs[0])
	for _, r := range rs[1:] {
		if unicode.ToLower(r) != first {
			return false
		}
	}
	return true
}
