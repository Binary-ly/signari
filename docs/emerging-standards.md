# Emerging standards: the complete inventory

Every specification this server implements that is not a settled RFC, enumerated
from `internal/` rather than from anybody's recollection, with its status
verified against the publisher in **August 2026**.

The point of the table is the denominator. "Four standards reviewed" means
nothing without knowing how many there are.

| package | specification | version and status | currency verified | reviewed in depth |
|---|---|---|---|---|
| `internal/authzen` | AuthZEN Authorization API | **1.0 Final**, 11 Jan 2026 | yes | **yes** — one conformance defect |
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

## What this sweep did not settle

76 of OpenID Federation's 121 mutants still survive, and 57 more never compiled —
the harness rewrites a guard to `if false`, which strands variables the body used.
Those 57 are unmeasured, not clean. The survivors are dominated by cache
plumbing, error-formatting branches and checks a later layer repeats, but "the
property holds by some other route" has been verified for the trust-chain rules
and assumed for the rest. Assumed is the honest word.

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
