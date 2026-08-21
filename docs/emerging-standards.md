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
