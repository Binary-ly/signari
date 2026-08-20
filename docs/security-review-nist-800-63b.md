# Security review: NIST SP 800-63B revision 4

RFC 9700 governs OAuth; **NIST SP 800-63B, Digital Identity Guidelines —
Authentication and Authenticator Management** governs the authentication itself.
This is the second half of the security-standard review.

Revision checked: **4**, the current one. That matters more than usual here,
because revision 4 changed the single number most implementations copied from
revision 3.

## The defect: a floor from the previous revision

`Policy.MinLength` was 8, with this comment:

> MinLength is the floor. NIST SP 800-63B sets 8 as the minimum acceptable

That was **correct for revision 3**. Revision 4 §3.1.1.2:

> Verifiers and CSPs SHALL require passwords that are used as a single-factor
> authentication mechanism to be a minimum of **15 characters** in length.
> Verifiers and CSPs MAY allow passwords that are only used as part of
> multi-factor authentication processes to be shorter but SHALL require them to
> be a minimum of eight characters in length.

This is the more dangerous kind of stale citation: it names a real document, the
number was right when written, and reading it feels like verification. Nobody
re-checks an accurate-looking reference.

The default is now 15, because the policy does not know whether a second factor
will be present. A deployment that enforces MFA on every account may lower it to
`MinLengthWithMFA`; one that does not, may not. Getting that wrong in the
permissive direction means single-factor passwords below a SHALL, so the default
is the number that is safe without knowing.

## The second defect, which I introduced while fixing the first

§3.1.1.2 also says:

> If Unicode characters are accepted in passwords, the verifier SHOULD apply the
> normalization process for stabilized strings using the Normalization Form
> Canonical Composition (NFC) normalization... **This process is applied before
> hashing the byte string that represents the password.**

The failure it prevents is concrete: "é" is one code point or two depending on
the keyboard, so a password set on one platform and typed on another is a
different byte string and simply does not verify — intermittently, for a minority
of users, with no error anybody can act on.

I implemented it inside `Policy.Check`, which takes the candidate **by value**.
The local copy was normalised, every check inside `Check` saw the right string,
and the caller then hashed the original. The SHOULD appeared to be implemented
and affected nothing.

That is precisely the defect class this review has been finding all session — a
control that looks present and is not — produced here by the fix for a different
one. It is recorded rather than quietly corrected because the lesson is that the
pattern is easy to write, not that other people write it.

Normalisation now lives in `Hasher.Hash` and `Hasher.Verify`, the only two places
a password becomes bytes, where no caller can bypass it.

`TestAHashOfOneUnicodeFormVerifiesTheOther` is the test that distinguishes the
two implementations: "both forms are accepted by the policy" passes either way;
"a hash of one verifies the other" only passes if the normalisation reached the
hasher. Removing it from the Hasher fails that test with the message naming the
cause.

Its fixtures are built from `\u00e9` and `e\u0301` escapes rather than literal
characters — the first version used two "café" literals that arrived
byte-identical, because something between the keyboard and the file normalised
them. The test compared a string with itself and tripped its own guard.

## Everything else in §3.1.1.2

| Requirement | Level | Signari |
|---|---|---|
| Minimum 15 for single-factor | SHALL | **was 8 — now 15** |
| Maximum at least 64 | SHOULD | 1024 |
| Accept all printing ASCII and space | SHOULD | yes |
| Accept Unicode | SHOULD | yes |
| Each code point counted as one character | SHALL | yes — counted in runes, not bytes |
| No other composition rules | **SHALL NOT** | none. The only mention of symbols is an error message explaining why they are not required |
| No periodic forced change | **SHALL NOT** | none |
| Force a change on evidence of compromise | SHALL | **yes** — `RecheckEvery` re-consults the breach corpus at sign-in |
| No password hints | SHALL NOT | none stored |
| No knowledge-based authentication | SHALL NOT | none |
| Verify the password in full, no truncation | SHALL | over-length is **refused**, never truncated |
| NFC before hashing | SHOULD | **now yes**, in the Hasher |
| Blocklist including breach corpora, dictionary words, and context-specific words such as the username | SHALL | yes — breach corpus, a common-word list, and a username/identity check |

The compromise-detection row is worth dwelling on, because it is the one where
the specification and the usual implementation diverge. §3.1.1.2 forbids periodic
rotation *and* requires a forced change on evidence of compromise. Most
implementations do the first and not the second — they rotate on a timer, which
the standard prohibits, and never re-check a password that was clean when chosen
and appeared in a breach corpus a month later.

`RecheckEvery` is the second: sign-in is the only moment the plaintext exists to
check again, and the corpus only grows.

## Verdict

One MUST-level defect from a stale revision, one SHOULD implemented and then
implemented properly, and eleven requirements that were already right — including
the two SHALL NOTs (composition rules, periodic rotation) that most password
policies violate by default.


---


**Revision 4 is final** and remains the current revision — `pages.nist.gov/800-63-4`
describes it as "the final version of SP 800-63, Revision 4". This review is
against the right document.


Full evidence, including the commands, is in `security-review-defaults.md`.

## The two SHALL NOTs this review had not covered (August 2026)

§3.1.1.2 carries two prohibitions as well as the length floor, and revision 4
raised **both** from revision 3's SHOULD NOT to **SHALL NOT**:

> "Verifiers and CSPs SHALL NOT impose other composition rules (e.g., requiring
> mixtures of different character types) for passwords."

> "Verifiers and CSPs SHALL NOT require users to change passwords periodically."

We comply with both, and did before this pass — there is no composition check
anywhere in `internal/passwords`, and no password-expiry column in any migration.
Two things were nonetheless wrong:

1. **The code described a SHALL NOT as advice.** `policy.go` said NIST "advises
   against" composition rules. That is revision 3's strength, quoted at revision
   4's number — precisely the stale-citation shape this document was written to
   record for `MinLength`. Corrected, and the requirement is now quoted rather
   than paraphrased.

2. **Compliance by absence had nothing holding it down.** Both requirements are
   satisfied by code that does not exist, which is the hardest kind to keep: a
   diff adding "must contain a digit" reads like tightening security, and nobody
   reviewing it is reminded that a standard forbids it.
   `TestNoCompositionRulesAreImposed` now accepts three passphrases with no
   uppercase, digit or symbol, so adding such a rule fails a test that says why.

The strength estimator is not a composition rule and the distinction matters: it
scores how many guesses a password would take, so a long lowercase passphrase
passes and `Password1!` does not — the opposite of what a composition rule does.

## §3.2 and §3.1's other verifier SHALLs (August 2026)

Read from the document's own section list rather than from this review's earlier
scope, which stopped at §3.1.1.2. Three more SHALLs bind a verifier that
implements what we implement.

| Requirement | Signari |
|---|---|
| §3.1.4 single-factor OTP: "Verifiers **SHALL** accept a given OTP only once while it is valid to provide replay resistance" | **met** — the last accepted counter is stored per credential and a repeat is refused (`TestReplayIsRefused`) |
| §3.1.2 look-up secrets: "A secret from a look-up secret authenticator **SHALL** be used successfully only once" | **met** — recovery codes are consumed by `UPDATE … WHERE used_at IS NULL`, so the row is spent by the statement that finds it and a concurrent second use affects no rows |
| §3.2.2 rate limiting: "The verifier **SHALL** limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 **by disabling that authenticator**" | **met for TOTP; deliberately deviated for passwords** — see below |

### The deviation, stated rather than glossed

**TOTP meets it comfortably.** `MaxTOTPFailures = 5` locks the credential, which
is twenty times tighter than the ceiling the SHALL sets.

**Passwords do not meet it as written.** The protection is a *windowed rate
limit* — 30 failures per 15 minutes per account, 20 per 5 minutes per address —
not a consecutive-failure counter that disables. An attacker willing to wait can
therefore exceed 100 consecutive failures; they simply take about fifty minutes
to do it.

That is a deliberate choice and the reasoning is in `server.go`: the per-account
key is **chosen by whoever submits the form**, so a counter that disables the
authenticator is a way to lock any named person out of their account on demand.
Complying with §3.2.2 literally would mean 100 guesses disables anybody — which
converts a brute-force defence into a denial-of-service primitive aimed at a
person the attacker names.

So the honest statement is not "met" and not "missed": it is a **known deviation
from a SHALL, taken to avoid a worse failure mode**, and it belongs in a
conformance conversation rather than in a tick-box. A deployment that needs
AAL2 conformance on paper needs to know about it, which is why it is now in
[TODO-FOR-YOU.md](../TODO-FOR-YOU.md) as a decision rather than settled here.

What would close it without the DoS: a very high consecutive-failure counter
(100, reset on any success) that triggers a *step-up requirement* rather than a
disable — the account stays reachable to its owner through a second factor, and
the attacker's 100 guesses buy them nothing. That is a design, not a patch, which
is the other reason it is a decision rather than a fix made here.

## §4's AAL requirements: reauthentication and phishing resistance (August 2026)

The sections above cover authenticators. §4's AAL requirements bind the *session*,
and were not examined.

### Reauthentication timeouts

| | Overall timeout | Inactivity timeout | Signari |
|---|---|---|---|
| AAL1 | SHALL exist; SHOULD ≤ 30 days | optional | met |
| AAL2 | SHALL exist; SHOULD ≤ 24 hours | SHOULD ≤ 1 hour | **overall met; inactivity absent** |
| AAL3 | **SHALL** ≤ 12 hours | SHOULD ≤ 15 minutes | **overall met exactly; inactivity absent** |

`sessionTTL = 12 * time.Hour` (`flow.go:34`), written to `sessions.not_after` at
creation and — as established in the V10.4.8 work — **never extended anywhere**.
So the overall timeout is a real ceiling rather than a sliding window: it satisfies
AAL2's SHOULD comfortably and lands exactly on AAL3's SHALL.

**There is no inactivity timeout.** A session idle for eleven hours is as good as
one used a minute ago. That misses AAL2's and AAL3's SHOULD — both are SHOULDs,
not SHALLs, so this is a deviation rather than a violation, but it was previously
unrecorded either way.

Worth being precise about what it would cost. An inactivity timeout needs a
`last_seen_at` written on each authenticated request, which is a write on the hot
path for every request — the reason it is usually implemented as a coarse
throttled update rather than a true one. That is a design with a performance
consequence, not a constant to change, which is why it is recorded here rather
than added quietly.

### Phishing resistance

> "Verifiers **SHALL** offer at least one phishing-resistant authentication
> option at AAL2."

**Met.** WebAuthn is implemented across eight routes — registration begin/finish,
assertion, the passkey signal endpoints (WebAuthn L3 `signalAllAcceptedCredentials`
and friends) — and the sign-in form carries `autocomplete="username webauthn"` so
conditional UI works. A passkey is origin-bound by construction, which is what
makes it phishing-resistant; TOTP and email OTP are not, and neither would satisfy
this on its own.

The SHALL is to *offer* one, not to require it, so having password-plus-TOTP
available alongside does not affect conformance.
