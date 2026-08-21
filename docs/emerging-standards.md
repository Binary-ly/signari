# Emerging standards: the complete inventory

Every specification this server implements that is not a settled RFC, enumerated
from `internal/` rather than from anybody's recollection, with its status
verified against the publisher in **August 2026**.

The point of the table is the denominator. "Four standards reviewed" means
nothing without knowing how many there are.

| package | specification | version and status | currency verified | reviewed in depth |
|---|---|---|---|---|
| `internal/authzen` | AuthZEN Authorization API | **1.0 Final**, 11 Jan 2026 | yes | **yes** — one conformance defect; re-verified Aug 2026 against the Final text: all five §10.1 endpoints at their default paths, and the §6.2 deny wire format now pinned |
| `internal/sdjwt` | Selective Disclosure for JWTs | **RFC 9901**, Standards Track, Nov 2025 | yes | **yes** — two inert tests |
| `internal/sdjwt` | SD-JWT VC | draft-18, 3 Aug 2026 | yes | **yes** — five wrong section numbers |
| `internal/txntoken` | Transaction Tokens | draft-11, 30 Jul 2026 (WG Last Call) | yes | **yes** — one defect |
| `internal/abca` | Attestation-Based Client Auth | draft-10, 6 Jul 2026 | yes | **yes** — two wrong-reason tests |
| `internal/uma` | UMA 2.0 Grant | Kantara Recommendation, 7 Jan 2018 | yes | **yes** — implemented Aug 2026 |
| `internal/oid4vci` | OpenID for Verifiable Credential Issuance | **1.0 Final**, 16 Sep 2025 | yes | **yes** — three untested key-source rules |
| `internal/oidfed` | OpenID Federation | **1.0 Final**, 17 Feb 2026 | yes | **yes** — two untested trust-chain rules |
| `internal/ssf` | Shared Signals Framework | **1.0 Final**, 29 Aug 2025 | yes | **yes** — three untested SET assertions |
| — | FAPI 2.0 Security Profile | **Final**, 22 Feb 2025, no errata | yes | **yes** — two MUST-level defects |

Ten specifications. All ten currency-verified against the publisher, and all ten
now put through a full review-and-mutate pass. The last three — OID4VCI, OpenID
Federation and SSF — were the ones that had been reviewed by reading only, and
mutating them found eight untested guarantees that reading had passed over,
including the two below.

## Two of them had moved without anybody noticing

- **SD-JWT** left draft and became **RFC 9901** in November 2025. The package
  still cited `draft-ietf-oauth-selective-disclosure-jwt` nine months later.
- **AuthZEN** reached **Final** in January 2026, superseding the Implementer's
  Draft the code was written against. `internal/authzen` recorded no version
  string at all, which is precisely how that happens.

Both are fixed, and every package above now names the text it implements. That is
the cheap control: a package that names its specification can be checked against
it, and one that does not can only be checked against somebody's memory.

`internal/ssf` was the third with no version recorded, found by building this
table, and now carries one.

## What "reviewed in depth" means here

Reading the specification's normative requirements against the code, then
deleting each guarantee in turn to see whether a test notices. The second half is
what found almost everything:

| found by | count |
|---|---|
| reading the specification | 3 defects |
| mutating the implementation | 14 untested or wrong-reason guarantees, 2 defects |

Reading finds requirements nobody implemented. Mutation finds requirements that
are implemented correctly but that no test constrains — either because the test
was never written, or because one exists whose name claims the rule and whose
assertion is satisfied by a different check entirely. The second kind is worse
than no test, because it reports coverage.
The second category is invisible to review and is where most of this session's
findings came from.

## The two worth naming

Both are in OpenID Federation's trust-chain validator, both were enforced
correctly, and both had a test whose name claimed to cover them.

**§10.2 step 6, the chain linkage.** `TestABrokenLinkIsRefused` breaks a link by
having the anchor vouch for a different entity *and* publish that entity's keys —
so the statement below it no longer verifies, and the chain is refused by the
signature check before the linkage check is consulted. Delete the linkage
comparison and no test fails. A chain assembled from individually-valid
statements about unrelated entities would validate.

**§10.2 step 4, `iss == sub` on the Entity Configuration.** Nothing tested it,
and nothing else catches it. An entity can sign a configuration with its own key,
carrying its own keys, naming *somebody else* as the subject: the self-signature
verifies against its own jwks, and the linkage rule is satisfied because the
issuer really is the entity the intermediate vouched for. With step 4 removed the
chain validates and resolves to

    Subject: https://victim.example   TrustAnchor: https://anchor.example

— entity impersonation with a fully valid chain behind it.

Both now have tests that isolate the rule: every signature verifies and every
other check passes, so the only thing that can refuse the chain is the rule under
test. Both kill their mutant.

## What this sweep did not settle, and one way it overstates

76 of OpenID Federation's 121 mutants still survive, and 57 more never compiled —
the harness rewrites a guard to `if false`, which strands variables the body used.
Those 57 are unmeasured, not clean. The survivors are dominated by cache
plumbing, error-formatting branches and checks a later layer repeats, but "the
property holds by some other route" has been verified for the trust-chain rules
and assumed for the rest. Assumed is the honest word.

**The harness runs only the mutated package's own tests** (`go test ./<pkg>/`),
so "survived" means *no test in that package* kills it — not that nothing
anywhere does. For a self-contained package the two coincide; for a package whose
guarantees are enforced through its callers they do not, and the survivor count
reads worse than the truth.

That was demonstrated rather than supposed. `Client.UnknownScopes` survived the
`internal/clients` sweep, which would make ASVS V10.4.11 look untested; running
the dependent packages with the guard disabled killed it immediately, via
`TestADeviceFlowCannotRequestScopesTheClientIsNotRegisteredFor` in
`internal/httpapi`. The property was tested all along, one package out.

The rule this leaves: a survivor is a *question*, not a finding. Re-run it
against the whole suite before believing it.

**A second flaw in the harness, and the fix.** Rewriting a guard to `if false`
drops the reference to whatever the condition mentioned, so every `if err != nil`
mutation left `err` declared and unused and simply failed to compile. In
`internal/tokens` that was **21 of 31 guards unmeasured** — and unmeasured reads
exactly like clean in a summary line.

Rewriting to `if false && (<original condition>)` keeps the variables referenced
while leaving the branch dead. On the same package the numbers went from
`killed=2, uncompilable=21` to `killed=6, killed_by_dependents=11,
uncompilable=6`. Two of the guards that became measurable for the first time were
the issuer checks in `VerifyIDTokenAudience` and `VerifyTyped`, which had never
been tested.

Both flaws pointed the same way: the harness was reporting less coverage than
existed in one direction and less measurement than it claimed in the other. Any
survivor count produced before these fixes should be read as an upper bound on
the gaps, not a count of them.

A caution that belongs with the technique: **a surviving mutant is not
automatically a defect.** Layered defences catch each other, so deleting one line
often leaves the system correct — three of ABCA's survivors and four of the JWT
verifier's are exactly that. The question is whether the property still holds by
some route, not whether one line is load-bearing.

## What is not here

Device posture (`internal/posture`) implements no published standard — it reads
evidence from headers an MDM sets, and is described in
[device-posture.md](device-posture.md). It is listed nowhere above because there
is no specification to be current with, which is worth stating rather than
leaving the reader to wonder why it is missing.

## A class of defect worth naming: the field that vanishes

AuthZEN's finding — `decision` would disappear from every deny if the bool ever
gained `omitempty` — turned out to be an instance of something general, so the
whole tree was swept for it: every boolean serialised with `omitempty`, where
`false` and "absent" mean different things to the receiver.

Five sites. Four are correct by construction and one needed a test:

| Site | Verdict |
|---|---|
| `oidc/metadata.go` `frontchannel_logout_supported`, `..._session_supported` | correct — the OIDC Front-Channel Logout spec *defines* omission as false, so omitting is what it asks for |
| `oidc/metadata.go` `backchannel_user_code_parameter_supported` | correct — `*bool`, so false is emitted and only unset is omitted |
| `scim/client.go` `primary` | correct — SCIM treats absent as false, and this is outbound |
| `tokens/idtoken.go` `email_verified` | correct, **now pinned** — see below |
| `authzen` `decision` | correct, **now pinned** — no `omitempty`, and the deny wire format is asserted |

### `email_verified`, and why both failure directions matter

OIDC Core §5.1: "True if the End-User's e-mail address has been verified;
**otherwise false**." Otherwise *false*, not otherwise absent. A relying party
deciding whether to trust an address needs "asserted, and not verified" to look
different from "not asserted" — several treat an absent claim as unknown and some
treat it as true, which makes a silently-dropped claim an account-linking hazard
at the receiving end.

The field is a `*bool`, always assigned when the email scope is granted. Two ways
to break it, and they are caught by different things:

- **plain `bool` with `omitempty`** — every unverified address goes quiet. This
  does not compile: `flow.go` assigns `&verified`, so the type change is caught
  at build time.
- **`*bool` without `omitempty`** — a token with no email scope emits
  `"email_verified":null`, asserting a claim it has no basis for. The compiler is
  happy; the new test is what catches it.

Neither was covered before. Worth separating because "the compiler protects it"
and "a test protects it" are different guarantees, and only one of them survives
somebody deciding to change both sites at once.

## Second-turn section sweeps, 21 August 2026

The reviews had concluded, from six second passes, that **"the risk is unread
sections, not misread ones"** — every finding came from a section a first pass
never opened. That is mechanisable: enumerate the specification's sections,
enumerate the ones our code and docs cite, and read the difference.

Five standards swept so far.

| Standard | Sections | Cited | Never cited | Outcome |
|---|---:|---:|---:|---|
| SSF 1.0 | 77 | 33 | 49 | **two defects** — §3.3 complex subjects resolved to nobody; §9.3's tolerance MUST correct but untested |
| RFC 9901 SD-JWT | 70 | 25 | 45 | none — most bind a Verifier, and we are issuer-only |
| OID4VCI 1.0 | 149 | 38 | 111 | none new; §14.3 correct-by-accident, now pinned by a test |
| Transaction Tokens draft-11 | 61 | 13 | 48 | none — see below |
| CIBA Core 1.0 | 35 | 14 | 21 | none — see below |
| AuthZEN 1.0 Final | 89 | 8 | 81 | mostly examples and registries; nothing binding unread |

Three of the six came back empty. That is worth recording rather than leaving as
silence: "swept and found nothing" and "never swept" are indistinguishable in a
repository a month later, and the whole value of the technique is knowing which
sections have had eyes on them.

### Transaction Tokens §11.2.1 and §11.2.2 — correctly refused, and named

Both define optional subject token types: a **self-signed JWT**
(`urn:ietf:params:oauth:token-type:self_signed`) and an **unsigned JSON object**
(`urn:ietf:params:oauth:token-type:unsigned_json`). Both are "A requester MAY
use", so supporting them is the TTS's choice.

`CheckSubjectTokenType` refuses both explicitly — *"defined by the specification
but not implemented here"* — rather than falling through to the generic "not a
type this deployment accepts". The distinction matters to an integrator: one
message says "you have misread the spec", the other says "this deployment does
not do that yet".

Refusing `unsigned_json` is the conservative reading and worth stating: accepting
it means taking the caller's `sub` entirely on trust, gated only by whatever
mutual authentication the deployment puts in front of the TTS. §13.5 exists for
that decision.

### CIBA §7.1.2 and §14 — verified, no change

**§7.1.2 User Code.** We advertise `backchannel_user_code_parameter_supported`
as **`false`** rather than omitting it, and the endpoint refuses a supplied
`user_code`. The reasoning is already in `metadata.go`: §7.1 gates the parameter
on this being true, "a client reading an absent field has to guess; a client
reading `false` knows not to send one".

**§14 Security Considerations.** Its `id_token_hint` guidance — that an OP should
accept hints whose expiry has passed, because the token is being used in a
context other than the one it was issued for — does not bind us: we accept
**`login_hint` only**, and refuse `id_token_hint` and `login_hint_token` with a
message naming what to use instead.

Checked rather than assumed that a subset is permitted. §7.1's REQUIRED is on the
**Client** — "it is REQUIRED that the Client provides one (and only one) of the
hints" — and the specification contains no corresponding requirement that an OP
accept all three. There is also no discovery parameter for which hints an OP
takes, so the error message is the only channel a client has; ours names the
supported one.

### What a sweep cannot tell you

It finds sections nobody read. It does not find a section that was read and
misjudged. The six passes that motivated this technique all failed the first
way — but that is evidence about those six, not a proof that the second way
never happens.

## Second turns by a different method: prohibition extraction (21 August 2026)

The section sweep above is one analytical pass. This is a second, deliberately
unlike it: rather than asking "which sections has nobody opened", extract every
**MUST NOT** in the document and check each prohibition against the code.

Prohibitions are the right target for a second pass. A missing MUST usually
breaks something and gets noticed; a violated MUST NOT is a thing that *works*,
which is why it survives.

### First, a check on the method itself

The FAPI 2.0 pass had just shown that an uppercase RFC 2119 sweep returns **zero**
against a specification using ISO Directive Part 2 lowercase keywords. Before
trusting any extraction, every specification's own conventions statement was
checked:

| Standard | uppercase | lowercase | declares |
|---|---:|---:|---|
| SSF 1.0 | 172 | 0 | RFC 2119/8174 |
| SD-JWT VC draft-18 | 137 | 2 | RFC 2119/8174 |
| Transaction Tokens draft-11 | 102 | 6 | RFC 2119/8174 |
| CIBA Core 1.0 | 107 | 22 | RFC 2119/8174 |
| ABCA draft-10 | 93 | 16 | RFC 2119/8174 |
| UMA 2.0 Grant | 81 | 8 | RFC 2119/8174 |
| OpenID Federation 1.0 | 538 | 18 | RFC 2119/8174 |
| OID4VCI 1.0 | 325 | 13 | RFC 2119/8174 |
| RFC 9901 | 118 | 12 | RFC 2119/8174 |
| **FAPI 2.0** | **0** | **94** | **ISO Directive Part 2** |

FAPI is the sole outlier, and every earlier uppercase extraction in this
repository was therefore valid. That is worth knowing rather than assuming: the
alternative was nine reviews resting on a method that had already failed once.

AuthZEN declares no conventions statement the search could find, but uses
uppercase keywords normatively throughout, so an uppercase extraction is correct
for it.

### A correction to the AuthZEN figures above

The AuthZEN sweep was run with a flattener that stripped `<script>` but not
`<style>`, so CSS text was counted as document headings. Corrected: **89
sections, 10 cited, 79 never cited** — against the 89 / 8 / 81 first reported.
The conclusion is unchanged, and the error is recorded because a number nobody
can reproduce is worse than no number.

### The prohibitions, checked

**Transaction Tokens** — 15 distinct MUST NOTs. Four bind us directly and all
four hold:

| Prohibition | Where it holds |
|---|---|
| "The Txn-Token Response MUST NOT include the `refresh_token` value" | never emitted; the response carries only RFC 8693's shape |
| "Authorization header MUST NOT be used because that may be used by the workloads for other purposes" | `Header = "Txn-Token"`, and the constant's comment gives this exact reason |
| "OAuth refresh tokens ... MUST NOT be used to request transaction tokens" | `CheckSubjectTokenType` refuses `SubjectRefreshToken`, citing §11.2 and §13.3 |
| "the Txn-Token MUST NOT contain the access token presented to the external endpoint" | the `Claims` struct has no such field — `sub`, `txn`, `req_wl`, `scope`, `tctx`, `rctx`, `req_wl_chain` and nothing else |
| §13.6 "MUST reject the Txn-Token Request and MUST NOT treat an unknown scope as unconstrained" | `ErrWiden` — "%q was not in the presented token" — an explicit refusal rather than a silent drop |

**ABCA** — 2 MUST NOTs, one of which binds an issuer: "A server MUST NOT include
a method it does not accept, and **the array MUST NOT be empty when the parameter
is present**." Both attestation metadata arrays carry `omitempty`, so an empty
list is absent rather than present-and-empty. Held by a struct tag, which is
worth noticing: nothing would fail if the tag were removed.

**SSF** — 13 MUST NOTs. The sharp one for a transmitter is "New event types MUST
use the top-level `sub_id` claim and MUST NOT use the `subject` field in the
events claim". We define no new event types; we emit the standard CAEP set, and
for those our transmitter deliberately populates both keys with the same value
for pre-1.0 receiver compatibility — which the same specification's §3.1.4
permits, and which the receiver-side ambiguity check enforces cannot disagree.

**UMA** — 9 MUST NOTs, most concerning claims-gathering redirection and PCTs,
neither of which this deployment implements.

### The remaining six, completing the method across all ten

**RFC 9901 (SD-JWT)** — 16 MUST NOTs. The three that bind an issuer are all
refused explicitly in `Payload`, each with its section already cited in the code
before this pass looked:

- §4.1 "The payload MUST NOT contain the claims `_sd` or `...`" — an
  always-visible claim by either name is refused, because the digest array would
  otherwise silently overwrite it and the credential would quietly not say what
  the configuration asked for.
- §4.2.1 the disclosure's claim name "MUST NOT be ... a claim name existing in
  the object as a permanently disclosed claim" — a name appearing in both the
  always and selective maps is refused, "revealing it would put the name in the
  payload twice".
- §4.1 "The same digest value MUST NOT appear more than once" — guarded, and the
  comment is precise about why the guard exists for **decoys** rather than real
  digests: real ones cannot collide, because the salts are unique and the hash is
  SHA-256.

**OID4VCI** — 26 MUST NOTs, largely mutual exclusions. §8.2's
"`credential_configuration_id` MUST NOT be present" when `credential_identifier`
is used is enforced, and the refusal explains the deeper reason: we issue no
authorization-details-driven identifiers, so "accepting it would mean resolving an
identifier we never handed out".

**CIBA** — 11 MUST NOTs. §7.1.1's "Authentication request parameters MUST NOT be
present outside of the JWT" governs signed authentication requests, which we do
not implement — and a `request` parameter is **refused rather than ignored**, so
the prohibition has no surface here. The push-mode prohibitions ("The OP MUST NOT
follow redirects") are inapplicable to a poll-only implementation.

**SD-JWT VC** — 19 MUST NOTs, most concerning Type Metadata and SVG rendering
templates, neither of which this issuer produces. The registered-claim rule
(`iss`, `nbf`, `exp`, `cnf`, `vct` "MUST NOT be included in the Disclosures") was
already covered by the `RedList` in `sdjwt.go`.

**AuthZEN** — 4 MUST NOTs, three of which bind a PDP client rather than an API
implementer.

**OpenID Federation** — 45 MUST NOTs, the largest set of the ten. The recurring
shape is "MUST NOT be the empty array `[]`" on `authority_hints` and related
claims, which our chain builder never emits empty.

### What this pass did not find

No new defect, across all ten. Recorded as a result rather than omitted: two
independent methods on the same documents — unread sections, then prohibitions —
now agree that the remaining exposure in these standards is not in what they
forbid.

The more interesting observation is *why* they came back empty. Nearly every
prohibition that binds us was already refused **with its section number in the
code comment**, written by an earlier pass. The prohibitions were not missed and
then found; they were handled and then re-verified by a method that did not know
that in advance. That is the outcome a second turn should have when the first one
was done properly, and it is worth distinguishing from a second turn that finds
nothing because it looked in the wrong place.

---

# Third pass: running each specification's own examples through our decoder

Two methods have been applied to these ten so far. Sweeping the sections nobody
had cited asks *what does the specification say that we never read*. Extracting
every prohibition asks *what must not happen*. Both read prose.


So: extract every JSON example from the specification, decode it with the types
that actually serve the API, re-encode, and compare.

## AuthZEN 1.0 Final

52 code blocks in the specification, 48 of which parse as JSON. `testdata/spec/`
now holds all 48, and `TestEverySpecExampleSurvivesDecoding` runs them.

The comparison rule is asymmetric, because not every difference is a defect:

| Difference | Verdict | Why |
|---|---|---|
| A field disappears | **failure** | either unmodelled or mismodelled |
| A value changes | **failure** | worse than losing it |
| An **empty** value appears | tolerated | Go zero values serialise; see below |
| A **non-empty** value appears | **failure** | inventing content |

### What it found in the test, before it found anything in the code

The first version of the classifier skipped every example that was a *bare
entity* — the `{"type","id","properties"}` and `{"name","properties"}` blocks that
§5.1–§5.3 use to define the entity shapes. They have no `subject` or `resource`
key, so nothing matched them.

That mattered more than it sounds. The full-request examples happen to carry
`properties` only on `action` and `resource`, never on `subject`. So renaming
`Subject.Properties`' JSON tag to `props` — a total break of §5.1's `properties`
member — left the entire suite green. The test asserted a coverage it did not have.

Fixed by classifying bare entities, and because §5.1 Subject and §5.2 Resource are
the identical three members on the wire, an example of one is checked as both. The
same mutation now fails in three examples. A corpus test that has never been shown
to fail is a corpus test that has not been shown to do anything.

### What it found in the code: nothing dropped, and one thing worth naming

No specification content is lost by any of our types. Four things that looked like
findings were checked and are not:

**`page` on Search requests** — appeared as dropped, and was the classifier again:
`SearchRequest` decodes `page.limit` and `page.token` correctly.

**§8.2's "identical to the preceding request"** — the same passage that defines
`next_token` also says all entities and pagination parameters MUST be identical to
the request that produced the token, and that PDPs SHOULD error otherwise. This is
implemented *and compared*: `pageOf` decodes the cursor, recomputes
`searchFingerprint(req)`, and refuses a mismatch by naming which entity changed.
A fingerprint computed and never compared is this review's most common finding;
this one is compared.

**`next_token` on an exhausted result set** — and here the specification disagrees
with itself. §8.2.2 says `next_token` is REQUIRED inside the page object and "If
there are no more results after this page, its value MUST be an empty string."
The specification's own example of a complete result set shows a page object with
`count` and `total` and **no `next_token`**. We follow the normative text and
always emit it — which also happens to satisfy a client written against the
example, since `""` is falsy everywhere a PEP is written. Recorded because the next
person to read that example will think we are wrong.

**Unknown members inside `options`** — dropped, and §10.1.1 requires receivers to
ignore unknown fields, so dropping is conformant. The half that matters is that
ignoring the unknown member must not cost the known one beside it: a decoder that
bails on the first unrecognised key would lose `evaluations_semantic` and silently
fall back to a semantic the caller did not ask for. Pinned by
`TestUnknownOptionsAreIgnoredWithoutLosingKnownOnes`.

### The one real finding: a latent defect that cannot fire yet

`Request.Subject` is a value, not a pointer. Once decoded, "this boxcar entry
omitted a subject" and "this entry sent an empty subject" are the same state, and
re-encoding an omitted subject produces `{"type":"","id":""}`.

As a PDP this is harmless, and provably so: `Request.Merge` applies batch defaults
**field by field**, which is what §6.3 requires, so an entry that omitted a subject
still inherits it. The corpus tolerates the artifact for that reason.

It stops being harmless the moment anything here *sends* an Evaluations body.
Nothing does — this package implements the PDP side, and a PDP only receives them —
but a PEP client built on these types would ship an explicit empty subject inside
every boxcar entry, and a PDP that merges all-or-nothing rather than field by field
reads that as "this entry overrides the default with nobody" instead of "this entry
didn't say".

This is the "correct by construction but unguarded" shape: the property holds
because of something we do not do, so nothing fails when we start doing it.
`TestBoxcarEntriesWouldMisreportAnOmittedSubject` does not assert the bug is absent
— structurally it is not. It asserts that the reasoning above still holds, and
skips itself with an instruction to delete it if the field ever becomes a pointer.

## SSF 1.0 — the third pass finds a real one

The decode-and-compare method does not transfer to SSF unchanged: our SET claims
are `map[string]any`, so nothing is ever dropped and a round-trip corpus would
report a clean sweep while proving nothing. The equivalent question for a
permissive decoder is not "did a field survive" but "does the receiver reach the
same conclusion the specification does". So the examples were pushed one layer
further in — through subject resolution, which is where this subsystem's last
defect lived.

### The finding

§3.1.4 says "Each Subject Member MUST refer to exactly one Subject Principal", and
the receiver enforces it in two places: `sub_id` beside `subject` within an event,
and the top-level `sub_id` beside either. Both call `subjectsDiffer`, which
compared a fixed list of member names:

```go
for _, k := range []string{"format", "iss", "sub", "email", "phone_number", "uri"} {
```

That is the membership of RFC 9493's *simple* formats and nothing else. The
identifier formats whose identity lives elsewhere were therefore invisible to it:

| Format | Identity lives in | Compared before |
|---|---|---|
| §3.3 complex | `user`, `device`, `session`, `tenant`, … | **no** |
| §3.2.6 aliases | `identifiers` | **no** |
| opaque | `id` | **no** |
| did | `url` | **no** |

Two complex subjects — one naming alice, one naming mallory — agree on `format`
("complex") and carry none of the six listed members. The loop compared six pairs
of absent values, found no difference, and reported them as the same principal.
The §3.1.4 check then passed, and a session-revocation SET naming two different
people was **accepted**.

Verified before it was believed and again after it was fixed: the two journey
tests fail against the old comparison and pass against the new one, and the
acceptance test — the same complex subject in both places, which is what a
conformant transmitter emits — passes under both.

### The fix, and why the list was the real defect

`subjectsDiffer` now compares every member present in **either** object. That
covers the four rows above and every format RFC 9493 has not yet registered.

The list is worth dwelling on, because the missing member names were not an
oversight so much as a maintenance obligation nobody could see: the comparison
was correct when it was written, and became wrong when the code started accepting
complex subjects — a change in a different file, which had no reason to know this
list existed. Nothing connected the two. A comparison keyed on what is *present*
has no such coupling, which is why the fix is a smaller thing than the list plus
four names.

`fmt.Sprint` is kept rather than `reflect.DeepEqual`: it preserves the existing
tolerance for a transmitter that sends `1` where another sends `"1"`, and Go
prints map keys in sorted order, so nested members compare stably.

### What made it findable

Not reading §3.1.4 — an earlier pass read it, quoted it, and implemented it. Not
extracting the prohibitions — it is in the prohibition list and was checked off,
correctly, because the rule *is* enforced. Both prose methods confirm a rule that
exists. Only running actual subject shapes through the actual comparison shows the
rule reaching six member names and stopping.

That is the same shape as the session's other findings and it is worth stating as
a general result: **a rule enforced in fewer places than its documentation claims
is invisible to any method that reads the documentation.**

## SD-JWT VC — the same staleness, one draft apart

The SSF finding suggested a mechanical sweep: every fixed list of field names used
for a comparison or a prohibition can go stale, because the list lives in one file
and the reason for each entry lives in a specification that keeps moving. Across
the emerging-standards packages there are exactly two such lists —
`processableSubjectMembers` in SSF, whose absences are deliberate and documented,
and `RedList` in SD-JWT.

`RedList` is the set of claims that MUST NOT be selectively disclosed. It held
`iss, iat, nbf, exp, cnf, vct, status, aud`.

### Checking it required first noticing the wrong document

The cached copy of the profile was **draft-10**, and the code cites **draft-18**.
Against draft-10 the analysis produced a confident, wrong answer — that `sub` was
missing from our list — because draft-10 §3.2.2.2 and draft-18 §2.2.2.3 are the
same section renumbered, and the section contains **two** lists whose members read
identically in a flat text extraction: the claims that cannot be selectively
disclosed, and the claims that can.

`sub` and `iat` are in the second list. Reading the first list's members as though
they were the section's members produces exactly the inverted conclusion. Recorded
because the failure was silent: the extraction succeeded, the output was
well-formed, and only pulling the surrounding sentence showed it was the wrong half
of the section.

### What draft-18 actually says, and what it cost us

| §2.2.2.3 | Claims |
|---|---|
| MUST NOT be selectively disclosed | `iss`, `nbf`, `exp`, `cnf`, `vct`, **`vct#integrity`**, **`aka_vcts`**, `status` |
| MAY be selectively disclosed | `sub`, `iat` |

Two claims were missing from ours, both added since the draft the list was copied
from:

**`vct#integrity`** is §5's hash of the Type Metadata document — the thing that
lets a verifier confirm the metadata it fetched is the metadata the issuer signed
over. Selectively disclosable, a holder withholds it and the verifier falls back
to trusting whatever that URL serves at verification time. That is precisely the
substitution §5 exists to prevent, and our library would have issued such a
credential without complaint.

**`aka_vcts`** is the credential's other declared types; withholding it hides what
else the credential claims to be.

And one deviation in the other direction: `iat` is on the **permitted** list in
both the profile and RFC 9901 §9.7, and we block it. That is stricter than either
specification. It is kept — nothing here needs a hideable issuance time — but it is
now recorded as a deviation with the condition that should end it: an ecosystem
whose Type Metadata marks `iat` as `"sd": "always"` (§9.3) cannot be served until
that entry goes.


An earlier version of our comment cited that agreement approvingly. It is worth
being careful about what it demonstrates: both lists were copied from the same
document at roughly the same time, so they agree about what that document said and
about what it has since added. Agreement between two implementations reading one
source is not independent confirmation, and the two claims neither of us carried
are the demonstration.

### The fix that matters is the test, not the two names

Adding `vct#integrity` and `aka_vcts` closes today's hole.
`TestRedListCoversEverySectionTwoTwoTwoThreeClaim` transcribes §2.2.2.3's first
list literally and asserts `RedList` covers it, asserts `sub` stays out, and fails
if the documented `iat` deviation is removed without updating the comment that
describes it. `TestTypeMetadataIntegrityCannotBeMadeSelectivelyDisclosable` goes
through `NewDisclosure` rather than the map, because a red list nothing consults
passes a map test.

Both die against the old list, with the message naming what a holder could
withhold.
