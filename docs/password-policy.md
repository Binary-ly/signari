# Password policy

One gate. Sign-up, recovery, the admin API and the CLI all call the same
function, because four checks in four places means one is eventually weaker —
and the weak one is the one an attacker uses.

## What is checked

| | |
|---|---|
| Length | A floor, **counted in characters, not bytes** |
| Context | Refuses a password containing the person's own username |
| Repetition | Refuses one character repeated |
| Reuse | Refuses the last N passwords |
| Breach | Refuses passwords in a known breach corpus |

## Guess strength

`SIGNARI_PASSWORD_MIN_SCORE` (default **3**, scale 0–4) refuses passwords that
would fall early to somebody who knows how people build them.

`Password123!` is twelve characters and satisfies every composition rule ever
written. `qwertyuiop12` is twelve characters. `aaaaaaaaaaaa` is twelve
characters. A length check passes all three and an attacker's first thousand
guesses contain all three.

Detected: keyboard walks, sequences, repeated characters, repeated blocks,
dates, leetspeak substitutions, a password built from your own name or address,
and a common password with digits or symbols bolted on. The score is a **guess
count**, because that is the unit an attacker actually spends.

The default of **3** was measured, not chosen: at a floor of 2, `Password123!`,
`Summer2026!`, `admin123` and even the four-character `gT4v` all pass — they
score exactly 2. A floor that admits the most-guessed password shape in the world
is not a floor.

**On by default**, unlike the breach check — it makes no network call and leaks
nothing, so there is no reason to make an operator opt in.

**It runs before the network check**, so the cheap structural test happens first
and the corpus is only consulted for passwords that already survived it.

**The word list is a few hundred entries, not thirty thousand.** The first
version shipped none at all, on the theory that the breach corpus covers common
words. Its own test disproved that immediately: `p@ssw0rd` scored 4/4, because
no *structural* pattern matches an English word, and the corpus is off by
default. Structure detection and a small list catch what a corpus cannot — a
password constructed from a cheap pattern that has never appeared in a dump.

## What is deliberately **not** checked

Composition rules — "one uppercase, one digit, one symbol". NIST SP 800-63B
advises against them: they push people towards `Password1!`, which is in every
breach corpus, and away from long passphrases, which are not.

Length and a breach check do the work those rules pretend to do. What they never
catch is context — `alice-was-here-2026` satisfies every composition rule ever
written and is guessable by anyone who knows Alice.

## The breach check, and how it differs from the alternatives

**The password never leaves the process.** The Have I Been Pwned range API is a
k-anonymity construction: we SHA-1 the candidate, send the **first five hex
characters** of the digest, and receive ~800 suffixes. The comparison happens
locally. The service learns a 20-bit prefix shared by roughly one password in a
million, and never sees the password, the digest, or which suffix matched.

We also send `Add-Padding: true`, so the *response size* cannot narrow down
which prefix was asked about to anyone watching the connection.

**An offline corpus is a first-class option.** Every comparable implementation
requires an outbound call on the path of a password change. Plenty of
deployments cannot make one — airgapped networks, regulated environments,
anywhere an outbound call from the identity provider is a review item. Point
`SIGNARI_PASSWORD_BREACH_LIST` at a file of SHA-1 hashes and the check runs with
no network at all. Both sources can be used together; the local one is consulted
first because it costs nothing and cannot fail.

**An unreachable corpus is not a verdict.** `ErrUnavailable` is distinct from
"not breached". By default the password is allowed through and the engine logs
at WARN, because a third party's outage should not stop a company changing
passwords. `SIGNARI_PASSWORD_BREACH_REQUIRED=1` refuses instead. Both are
defensible; choosing silently is not, which is why it is a setting rather than a
default nobody sees.

**Padding entries are not matches.** The API returns decoy suffixes with a count
of `0`. Treating one as a match would refuse a password that is not in the
corpus at all — and the padding exists precisely so responses are
indistinguishable.

## Re-checking, which nothing else does

Every comparable implementation checks a password once — at the moment it is
chosen — and never again. Corpora only grow, so the control quietly expires the
day after it ran: a password that was clean in January and turned up in a March
dump is still treated as clean in December.

Sign-in is the only moment the plaintext exists to check again.
`SIGNARI_PASSWORD_BREACH_RECHECK_DAYS=30` re-consults the corpus at most once per
month per credential, **after** the password has been verified — checking before
verification would turn the login form into an oracle for asking whether an
arbitrary string is breached.

A hit **flags rather than refuses**. The person is standing at a login box with a
password that works; the useful outcome is that they leave with a different one,
not that they are turned away with nowhere to go. The next sign-in routes to a
change-password page before any session exists.

The stamp is recorded whatever the verdict, **including when the corpus was
unreachable** — otherwise an outage becomes a retry on every sign-in by every
user, and a third party's bad hour becomes ours.

## Requiring a change

`must_change` on the credential. Three things set it:

| | |
|---|---|
| Re-checking | The password turned up in a corpus after it was chosen |
| Migration | A password brought from the old IdP is in a corpus |
| An administrator | `{"require_password_change": true}` on the user endpoint |

The gate lives in `completeSignIn`, beside the prompt check, for the same reason
that one does: there are eight ways to sign in, and a gate written at each of
them is a gate missing from one of them.

**A reason is always shown.** An unexplained demand to change a password is
indistinguishable from phishing, and a user trained to comply with unexplained
demands is the vulnerability the demand was meant to fix.


**Setting a password clears the flag, the throttle counters and the stamp.** They
belonged to the password being replaced. A stale flag means a user changes their
password as instructed and is asked to do it again — a loop with no exit from
their side.

## Reuse

`SIGNARI_PASSWORD_HISTORY=3` keeps the last three Argon2id hashes and refuses a
candidate matching any of them.

The outgoing hash is recorded **before** it is replaced. Recording it afterwards
would file the new password as a previous one and refuse it at the next change —
a bug that only appears on the second reset.

Hashes beyond the configured depth are trimmed. Credential-adjacent material
kept past the question it answers is exactly what a retention policy exists to
prevent.

## Where the check runs in the recovery flow

**After** the reset token is validated, not before — because the reuse and
context checks need to know whose password this is.

The cost is that "too short" is reported after the token is checked. That is the
right way round: a message about password length must never tell somebody
holding a stale link that the link was otherwise valid.

## Verification

Nine tests, and each guard was checked by breaking it and confirming a test
noticed — including one where my first mutation hit the wrong branch of three
identical `ErrUnavailable` returns and I had to redo it against the path the
test actually exercises.
