# Password policy

## Introduction

A password policy is the set of checks a new password must pass. If sign-up,
recovery and administration each checked passwords their own way, one of them
would eventually be weaker. The weak one is the one an attacker uses.

Signari has one gate. Sign-up, recovery, the Admin API and the command line all
call the same function. It checks a password's length, and how hard it would be
to guess. When you turn them on, it also refuses reused passwords and passwords
from known breaches.

You set the policy with the `SIGNARI_PASSWORD_` environment variables named on
this page. [Every environment variable](configuration.md) lists each one with
its default.

## What is checked

Every new password goes through these checks:

| | |
|---|---|
| Length | A floor, **counted in characters, not bytes** |
| Context | Refuses a password containing the person's own username |
| Repetition | Refuses one character repeated |
| Reuse | Refuses the last N passwords |
| Breach | Refuses passwords in a known breach corpus |

A "breach corpus" is a collection of passwords that have leaked in past
breaches.

## Guess strength

`SIGNARI_PASSWORD_MIN_SCORE` refuses passwords that would fall early to somebody
who knows how people build them. Its default is **3**, on a scale of 0–4.

`Password123!` is twelve characters, and satisfies every composition rule ever
written. `qwertyuiop12` is twelve characters. `aaaaaaaaaaaa` is twelve
characters. A length check passes all three, and an attacker's first thousand
guesses contain all three.

The check detects:

- keyboard walks;
- sequences;
- repeated characters and repeated blocks;
- dates;
- letters swapped for look-alike digits or symbols, called "leetspeak";
- a password built from the person's own name or address;
- a common password with digits or symbols bolted on.

The score is a **guess count**, because that is the unit an attacker actually
spends.

The default of **3** was measured, not chosen. At a floor of 2, `Password123!`,
`Summer2026!`, `admin123` and even the four-character `gT4v` all pass: they
score exactly 2. A floor that admits the most-guessed password shape in the
world is not a floor.

**It is on by default**, unlike the breach check. It makes no network call and
leaks nothing, so there is no reason to make an administrator opt in.

**It runs before the network check.** So the cheap structural test happens
first, and the corpus is consulted only for passwords that already survived it.

**The word list is a few hundred entries, not thirty thousand.** The first
version shipped none at all. The theory was that the breach corpus covers
common words. Its own test disproved that at once: `p@ssw0rd` scored 4/4. No
*structural* pattern matches an English word, and the corpus is off by default.
Structure detection and a small list catch what a corpus cannot: a password
built from a cheap pattern that has never appeared in a leak.

## What is deliberately not checked

**Composition rules**, such as "one uppercase, one digit, one symbol". The
National Institute of Standards and Technology (NIST) covers them in
NIST SP 800-63B-4 §3.1.1.2. It says verifiers SHALL NOT impose them, where
revision 3 said SHOULD NOT. They push people towards `Password1!`, which is in
every breach corpus, and away from long passphrases, which are not.

Length and a breach check do the work those rules pretend to do. What the rules
never catch is context. `alice-was-here-2026` satisfies every composition rule
ever written, and anyone who knows Alice can guess it.

**Periodic expiry**, such as "change your password every 90 days". The same
section says verifiers SHALL NOT require it. A password that expires on a
schedule becomes the previous one with a digit changed. Instead, a password is
changed when there is evidence it is compromised. With the breach check on, a
password found in a breach corpus at sign-in is flagged. The person is asked to
change it before the session is issued.

Both are compliance by absence: there is no composition check and no expiry
column. Absence is the hardest thing to keep, because a change that adds either
reads like tightening security. `TestNoCompositionRulesAreImposed` and
`TestNoPasswordExpiresOnASchedule` fail the build if either appears.

This was recorded as a decision in October 2026. A procurement checklist that
asks for either is asking for what the standard forbids, and the answer is this
page.

## The breach check, and how it differs from the alternatives

**The password never leaves the process.** Signari uses the range API of Have I
Been Pwned, a public breach corpus. That API is a "k-anonymity" construction:
the service learns only something that many passwords share.

Signari hashes the candidate password with SHA-1, and sends the **first five hex
characters** of the hash. It receives about 800 suffixes back, and the
comparison happens locally. The service learns a 20-bit prefix shared by
roughly one password in a million. It never sees the password, the hash, or
which suffix matched.

Signari also sends `Add-Padding: true`. Then anyone watching the connection
cannot use the *response size* to narrow down which prefix was asked about.

**An offline corpus is a first-class option.** A check that needs an outbound
call puts one on the path of every password change. Plenty of deployments cannot
make one, such as air-gapped networks and regulated
environments. Others treat any outbound call from the identity provider (IdP)
as an item to review.

Point `SIGNARI_PASSWORD_BREACH_LIST` at a file of SHA-1 hashes, and the check
runs with no network at all. You can use both sources together. The local one is
consulted first, because it costs nothing and cannot fail.

**An unreachable corpus is not a verdict.** `ErrUnavailable` is distinct from
"not breached". By default, the password is allowed through, and the engine logs
at WARN level. A third party's outage should not stop a company changing
passwords. `SIGNARI_PASSWORD_BREACH_REQUIRED=1` refuses instead.

Both choices are defensible. Choosing silently is not, which is why it is a
setting and not a default nobody sees.

**Padding entries are not matches.** The API returns decoy suffixes with a count
of `0`. Treating one as a match would refuse a password that is not in the
corpus at all. The padding exists precisely so that responses are
indistinguishable.

## Re-checking a password at sign-in

A password checked only once, at the moment it is chosen, is never checked
again. Corpora only grow, so that control quietly expires the day after it ran.
A password that was clean in January and turned up in a March leak would still be
treated as clean in December.

Sign-in is the only moment the plaintext exists to check again.
`SIGNARI_PASSWORD_BREACH_RECHECK_DAYS=30` re-consults the corpus at most once
per month per credential. It does so **after** the password has been verified.
Checking before verification would turn the sign-in form into an "oracle": a
way for anyone to ask whether an arbitrary string is breached.

A hit **flags rather than refuses**. The person is standing at a sign-in box
with a password that works. The useful outcome is that they leave with a
different one, not that they are turned away with nowhere to go. The next
sign-in routes to a change-password page before any session exists.

Signari records the time of each re-check, its "stamp", whatever the verdict.
That **includes when the corpus was unreachable**. Otherwise an outage would
become a retry on every sign-in by every person, and a third party's bad hour
would become Signari's.

## Requiring a change

A flag on the credential, `must_change`, asks the person to change their
password. Three things set it:

| | |
|---|---|
| Re-checking | The password turned up in a corpus after it was chosen |
| Migration | A password brought from the old IdP is in a corpus |
| An administrator | `{"require_password_change": true}` on `PATCH /admin/users/{userID}` |

The gate lives in `completeSignIn`, beside the prompt check, for the same reason
that one does. There are eight ways to sign in, and a gate written at each of
them is a gate missing from one of them.

**A reason is always shown.** An unexplained demand to change a password is
indistinguishable from phishing. A person trained to comply with unexplained
demands is the vulnerability the demand was meant to fix.

**Setting a password clears the flag, the throttle counters and the stamp.**
They belonged to the password being replaced. A stale flag would mean a person
changes their password as instructed, and is asked to do it again. That is a
loop with no exit from their side.

## Reuse

`SIGNARI_PASSWORD_HISTORY=3` keeps the last three Argon2id hashes, and refuses
a candidate matching any of them.

The outgoing hash is recorded **before** it is replaced. Recording it afterwards
would file the new password as a previous one, and refuse it at the next change.
That bug would appear only on the second reset.

Hashes beyond the configured depth are trimmed. Material close to a credential,
kept past the question it answers, is exactly what a retention policy exists to
prevent.

## Where the check runs in the recovery flow

The check runs **after** the reset token is validated, not before. The reuse and
context checks need to know whose password this is.

The cost is that "too short" is reported after the token is checked. That is the
right way round. A message about password length must never tell somebody
holding a stale link that the link was otherwise valid.

## Verification

Nine tests cover this page. Each guard was checked by breaking it on purpose,
and confirming that a test noticed.

In one case, the first break hit the wrong branch of three identical
`ErrUnavailable` returns. It had to be redone against the path the test
actually exercises.
