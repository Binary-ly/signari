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
| `internal/oid4vci` | OpenID for Verifiable Credential Issuance | **1.0 Final**, 16 Sep 2025 | yes | earlier pass; not re-mutated |
| `internal/oidfed` | OpenID Federation | **1.0 Final**, 17 Feb 2026 | yes | earlier pass; not re-mutated |
| `internal/ssf` | Shared Signals Framework | **1.0 Final**, 29 Aug 2025 | yes | earlier pass; not re-mutated |
| — | FAPI 2.0 Security Profile | **Final**, 22 Feb 2025, no errata | yes | **yes** — two MUST-level defects |

Ten specifications. All ten currency-verified against the publisher. Six put
through a full review-and-mutate pass; three reviewed in earlier passes and
confirmed current but not re-mutated; one implemented from the specification this
month.

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
| mutating the implementation | 6 inert or wrong-reason tests, 2 defects |

Reading finds requirements nobody implemented. Mutation finds requirements
everybody believed were implemented and tested, where the test could not fail.
The second category is invisible to review and is where most of this session's
findings came from.

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
