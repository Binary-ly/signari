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

## §5 Session Management: reauthentication, and §2's phishing resistance (August 2026)

The sections above cover authenticators. Reauthentication binds the *session* and
was not examined.

**A numbering correction I owe this document.** An earlier version of this
section was headed "§4's AAL requirements". That is wrong twice over: SP
800-63B-4's §2 is *Authentication Assurance Levels*, §4 is *Authenticator Event
Management*, and the reauthentication timeouts live in **§5 Session Management**.
The requirements quoted below were right; the section number attached to them was
not. Same defect class as the three citation errors this review already records —
and made while writing the section that records them.

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

## §4 Authenticator Event Management — the section nothing had checked

SP 800-63B-4 §4 governs what happens across an authenticator's life: binding,
loss, compromise, revocation. This review had never opened it.

| Requirement | Signari |
|---|---|
| §4.1.2.1: "When an authenticator is added, the CSP **SHALL** notify the subscriber via a mechanism independent of the transaction binding the new authenticator" | **not met** — see below |
| §4.3: "**SHALL** suspend, invalidate, or destroy compromised authenticators … promptly following compromise detection" | met — a credential can be removed from the account screen, and a session compromise revokes the refresh lineage |
| §4.5: "**SHALL** promptly invalidate authenticators when a subscriber account ceases to exist …, when requested by the subscriber, when the authenticator is compromised …" | met |
| §4.5: "**SHOULD** notify the subscriber when an authenticator is invalidated" | not met, same cause |

### The gap: adding an authenticator is silent

Enrolling a **passkey** or a **TOTP credential** writes an audit event and sends
nothing. Enrolling an **email OTP** address does send mail — but that is the
confirmation code, part of the binding transaction rather than independent of it,
which is precisely the distinction §4.1.2.1 draws. (It does carry the right
warning: *"If you did not ask to use this address for sign-in codes, somebody may
be signed in to your account."*)

**Why the independence matters, concretely.** The attack this requirement exists
for is: somebody obtains a live session — a stolen cookie, a borrowed laptop, a
session fixed before the victim noticed — and enrols *their own* authenticator.
They now hold a credential of their own on the victim's account, which survives a
password change. The victim's only signal is an audit entry they will never read.
A message to an address the attacker does not control is what turns that into
something the victim can act on within minutes.

An audit event is not a substitute. It is a record for whoever investigates
afterwards; a notification is a control that reaches the person who can stop it.

### Why this is recorded rather than fixed

The mailer exists and the enrolment paths already reach it, so the code is small.
What is not small is the decision around it: which channel is "independent" when
the account may have only one address, what happens when mail delivery fails
mid-enrolment (refuse the binding, or bind and log?), and whether an SMS-enrolled
account should be told by mail or by SMS. Getting that wrong makes enrolment
fragile in a way users experience immediately.

It is in [TODO-FOR-YOU.md](../TODO-FOR-YOU.md) as **9h**, and it is the first
NIST gap this review has found that is a plain **SHALL** with no deviation
argument behind it — unlike §3.2.2's rate limiting, where the deviation is
deliberate and defensible.

## §5 Session Management, completed

The reauthentication timeouts above are §5's, but §5 also binds the session
*secret* itself. Seven requirements, all checked against source.

| §5 requirement | Signari |
|---|---|
| "established using input from an approved random bit generator … **at least 64 bits** in length" | **256 bits** — `newSID` reads 32 bytes from `crypto/rand.Reader`, four times the floor |
| "**SHALL** be generated by the session host in direct response to an authentication event" | yes — minted at sign-in, never derived from anything the client supplies |
| "tagged to be accessible only on secure (i.e., HTTPS) sessions" | `Secure: true` |
| "tagged as inaccessible via JavaScript (i.e., HttpOnly)" | `HttpOnly: true` |
| "SameSite=Lax" or "SameSite=Strict" | `SameSiteLaxMode`, and the choice is reasoned in place: Strict drops the cookie on the top-level redirect back from an external IdP, so the user lands logged-in-but-not-recognised |
| "accessible to the minimum practical hostnames and paths" | the cookie is named `__Host-signari_session`, and the `__Host-` prefix *forbids* a `Domain` attribute at the browser — stricter than the requirement, and enforced by the user agent rather than by us remembering |
| "contain only an opaque string … **SHALL NOT** contain cleartext personal information" | an opaque 256-bit value. The code is explicit about why it is not the `sid`: *"this value is a bearer credential and must never be published, whereas the sid it resolves to is public and appears in every ID token. Conflating the two is how an ID token becomes a session-stealing primitive."* |
| "erased or invalidated by the session subject when the subscriber logs out" | both halves — `clearSessionCookie` expires it at the browser, and `store.TerminateSessions` (the only function permitted to end a session) revokes it server-side, so a retained cookie is worthless |

Nothing to fix. Recorded because "we meet it" and "we checked" are different
claims, and this section had only ever had the second half assumed.

### That closes 800-63B-4's normative sections

§2 (AAL), §3 (authenticators and verifiers), §4 (authenticator event management)
and §5 (session management) have now each been read against source. §6, §7 and §8
— Security, Privacy and Customer Experience Considerations — are **informative**
and carry no verifier SHALLs.

One unmet SHALL stands: **§4.1.2.1's binding notification** (TODO 9h). One
deliberate deviation stands: **§3.2.2's consecutive-failure limit** for passwords
(TODO 9e), taken to avoid a targeted denial-of-service. Everything else in the
normative sections is met, and now says where.

## Syncable authenticators and account notifications (20 August 2026)

Re-read against the published text rather than from notes, using the document's
own headings. Two areas that had not been checked line by line before.

### Appendix: Syncable Authenticators — normative, and we satisfy it

The appendix states outright that it "is normative". Its verifier requirements
are about WebAuthn Level 3 flags, which is the same ground as the backup-flag
defect fixed earlier this session — so the two pieces of work meet here.

| Requirement | Ours |
|---|---|
| UP — "Verifiers SHOULD confirm that the User Present flag has been set" | the library verifies it on every assertion |
| UV — "Verifiers SHALL indicate that UV is preferred **and SHALL inspect responses to confirm the value of the UV flag**" | we go further than "preferred": `BeginLogin` and `BeginDiscoverableLogin` both pass `VerificationRequired`, and `amrForPasskey` reads the returned flag |
| **"If the user is not verified, agencies SHALL treat the authenticator as a single-factor cryptographic authenticator"** | `amrForPasskey` adds `mfa` **only** when `UserVerified`, and `ACRFromAMR` then yields `ACRSingleFactor` — tested in `amr_test.go` across all four flag combinations |
| BE — "necessary to distinguish authenticators that are device-bound from those that may be cloned" | stored as of this session, and emitted as `hwk` vs `swk` in `amr` |
| BS — "Agencies SHOULD NOT condition acceptance based on this flag for public-facing applications" | we do not condition acceptance on it; it is recorded, and a 1→0 transition is audited |

The single-factor rule is the one worth calling out. A tapped security key with no
PIN or biometric proves possession and nothing else, and `amr_test.go`'s first
case asserts exactly that: `["user","hwk"]`, `acr` single-factor. If that yielded
multi-factor, a tap would silently satisfy every MFA requirement in the system.

### Account Notifications — one SHALL closed, one still open

> "When an authenticator is added, the CSP SHALL notify the subscriber via a
> mechanism independent of the transaction binding the new authenticator"

**Was unmet; now implemented.** Registering a passkey emails the account holder
after the commit, naming the authenticator, with instructions for the case where
it was not them and contact information — which is the other half of the
requirement:

> "The notification SHALL provide clear instructions, including contact
> information, in case the recipient repudiates the event associated with the
> notification."

Three details that are the requirement rather than decoration:

- **Independent of the transaction.** Email, not a banner on the page that just
  did it. Whoever is holding the browser is exactly who must not be the only one
  who finds out.
- **After the commit.** A notice about a registration that then rolled back
  teaches the recipient that these messages are noise, which is the one thing a
  security notification cannot afford.
- **A send failure does not undo the registration.** The credential is real by
  then and refusing it would leave the user holding an authenticator the server
  has forgotten. It is audited as `mfa.passkey_notice_failed` so an operator can
  see that a required notification did not go out.

The threat is concrete: an attacker with momentary control of a session — a
borrowed laptop, a stolen cookie — registers their own passkey and obtains
durable access outliving the session they took. Nothing told the owner, and the
credential list is a page nobody visits.

> "CSPs SHALL support at least two notification addresses per subscriber account."

**Still unmet.** We model one email address per user, so the notice reaches
exactly one place — and if that mailbox is the one the attacker holds, it reaches
nobody who matters. Recorded as **9l**: which channels to support is a decision
about the product, and the schema and send path follow from it.

## §4.5 Invalidation: the subscriber could not request it (21 August 2026)

> "CSPs SHALL promptly invalidate authenticators when a subscriber account ceases
> to exist..., **when requested by the subscriber**, when the authenticator is
> compromised, or when the CSP determines that the subscriber no longer meets its
> eligibility requirements."

There was no way to make the request. `store.DeleteCredential` was written, given
an ownership check and a last-credential guard, tested — and **had no caller
anywhere in the tree**. No route, no CLI path, no admin path. Registering a
passkey was possible; removing one was not.

**The notification added the day before made it worse by naming it.** That notice
says: "If you did NOT add it, someone else may have had access to your account.
Sign in, remove the passkey you do not recognise, and change your password." The
instruction was unfollowable. A security notification that tells someone to do
something the product does not permit is worse than one that says nothing,
because it spends the reader's trust on a dead end.

`POST /account/passkeys/delete` now exists. Three properties, each tested:

- **The last credential cannot be removed** — `ErrWouldLockOut`, enforced in the
  store where the count and the delete share one transaction, because two
  concurrent requests each seeing "two remain" would otherwise leave zero.
- **Another user's credential cannot be removed**, and the answer is the same 404
  whether it does not exist or belongs to somebody else. Distinguishing them
  would confirm which uuids are real.
- **CSRF is required.** Kill-checked: with the guard removed, a request carrying
  only a session cookie removes a passkey. Stripping a factor is exactly what a
  cross-origin post would want, and the account it targets is one the attacker
  already knows is signed in somewhere.

§4.5 also says "The CSP SHOULD notify the subscriber when an authenticator is
invalidated, as described in Sec. 4.6", so removal now sends the mirror of the
binding notice. The threat is the mirror too: an attacker who *removes* a factor
has made the account weaker, and a thing that is simply gone is the hardest change
for its owner to notice.

## §5.2 session timeouts, checked against the AAL tables

> "Periodic reauthentication of subscriber sessions SHALL be performed... A
> definite reauthentication overall timeout SHALL be established, which SHOULD be
> no more than 24 hours at AAL2. The inactivity timeout SHOULD be no more than 1
> hour."

**The overall timeout SHALL is met**: sessions carry `not_after`, `SweepExpiredSessions`
ends them at it, and every session lookup filters on `not_after > now()` — so an
expired session is dead to a reader even before the sweep runs.

**The inactivity timeout SHOULD is not met**, which is item **9f** and was already
recorded. Reading §5.2 sharpens why it matters rather than changing the verdict:
"Session activity SHALL reset the inactivity timeout" — so the feature is not a
second expiry column, it is a write on every authenticated request, and that is a
cost worth deciding deliberately rather than adding by reflex.

One thing that reads like a defect and is not: our session cookie carries no
`MaxAge`, which the original plan called a mismatch against the 12-hour database
value. §5.2 is explicit that this is correct — "Session secrets that are used as
bearer tokens for session management SHOULD NOT be persistent (i.e., retained
across a restart of the associated application or a reboot of the host device)".
A cookie with no `MaxAge` is a session cookie, which is exactly what the sentence
asks for. The database holds the authoritative lifetime; the browser holds one
that dies with the browser.
