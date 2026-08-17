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
	// MinLength is the floor. NIST SP 800-63B sets 8 as the minimum acceptable;
	// longer is better and this is a floor rather than a recommendation.
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

// DefaultPolicy is what a deployment gets without configuring anything.
func DefaultPolicy() Policy {
	return Policy{MinLength: 8, MaxLength: 1024}
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
		min = 8
	}
	max := p.MaxLength
	if max <= 0 {
		max = 1024
	}

	// Counted in RUNES. len() on a Go string is bytes, so a passphrase in a
	// non-Latin script would be measured as several times its real length and a
	// short one would pass a check it should fail.
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
