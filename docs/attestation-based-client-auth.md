# Attestation-based client authentication

## Introduction

An application that runs on a person's own device, such as a mobile application,
cannot keep a secret. So Signari cannot tell the genuine application from a copy
of it. "Attestation-Based Client Authentication" (ABCA) lets a trusted third party
vouch for the genuine one.

Signari implements the draft standard
`draft-ietf-oauth-attestation-based-client-auth-10`, of 6 July 2026, the current
draft at the time of writing. It verifies the attestation and a fresh proof from
the device at the token endpoint.

You register the public keys of an attester you trust with
`signari attester add`. See [every command](cli.md).

## The problem

A public client has no secret. Anything holding its `client_id` is
indistinguishable from the real one, because there is nothing to prove otherwise.
That could be a repackaged application, a script or a modified build.

Proof Key for Code Exchange (PKCE, see the [glossary](glossary.md#pkce)) binds a
code to a one-time secret. Demonstrating Proof of Possession ([DPoP](dpop.md))
binds a token to a key. Neither says anything about **what** holds that key. A
repackaged application generates a perfectly good DPoP key, and produces
perfectly good proofs.

ABCA adds a third party. A **Client Attester** vouches that a particular key
belongs to a genuine instance of a known application. The instance then proves it
holds that key.

So the token endpoint learns two things it could not learn before. This is the
application Signari thinks it is, and this is the instance the attester saw.

## Two artefacts

The application sends two headers, each holding a signed JSON Web Token (JWT):

```
OAuth-Client-Attestation:      signed by the ATTESTER, carries cnf.jwk
OAuth-Client-Attestation-PoP:  signed by the INSTANCE key named in that cnf
```

The first is long-lived and reusable. The second, the "proof of possession"
(PoP), is per-request. That split is what lets an attester issue an attestation
once, offline, while the instance proves liveness on every call. It is also the
reason `typ` matters so much, as described below.

## Decisions the draft leaves open

**Symmetric attester keys are refused.** §4 permits an attestation to be "signed
or integrity protected with a Message Authentication Code". Signari accepts
asymmetric signatures only.

A symmetric attester key is a key *Signari holds*. So Signari could mint
attestations indistinguishable from the attester's own. An attestation Signari
could have forged itself vouches for nothing. It would be worth exactly as much as
trusting the `client_id` Signari already had.

The command line refuses to register a JSON Web Key Set (JWKS) containing private
keys, for the same reason. It refuses at the moment somebody makes the mistake.

**A challenge is mandatory, because Signari offers the endpoint.** §5.1 makes the
`challenge` claim OPTIONAL. But §6.1 is unambiguous once an endpoint exists: "If
the Authorization Server offers a challenge endpoint, the Client MUST retrieve a
challenge and MUST use this challenge."

**Challenges are single-use.** The draft does not require it. Single use is what
makes a captured PoP *worthless* rather than merely short-lived. It costs one
`UPDATE … WHERE used_at IS NULL`, the same technique authorization codes and
credential nonces use here.

**`jti` replay detection as well.** It is belt and braces while challenges are
mandatory. It is also the thing that still works if a deployment later turns
challenges off.

## Testing

Every rule of §7.1 and §7.2 has a test that makes exactly one thing wrong, so a
failure names the rule. Then each was mutated, broken on purpose, to confirm it
can fail. Two mutations survived the first pass, and both were real gaps.

**The PoP `typ` check was untested.** The attestation had a `typ` test, and the
PoP did not. The case that matters is substituting an **attestation** as a PoP.
Both are signed JWTs, and the attestation is the long-lived artefact that travels
in a header on every single request.

Without the `typ` check, anyone who captured one could present it as the
per-request proof. Nothing else in the verifier would have objected. That is
exactly the cross-protocol substitution `typ` exists to prevent, and the test
suite could not see it.

**Three branches turned out to be diagnostic, not load-bearing:**

- An absent `exp` decodes to zero, and is refused as "expired in 1970".
- An absent `challenge` fails the store lookup, and is refused as "unknown or
  expired".
- A missing DPoP proof fails a constant-time compare on length.

All are safe, and all give the wrong message. Each sends an integrator to
investigate a clock, an expiry or a key mismatch that never happened. Those
branches are now tested on the message, which is what they actually buy.

This is the fourth and fifth time this pattern has appeared in this codebase. The
rule it keeps producing is *a check that cannot be made to fail is not yet known
to be doing anything*. Sometimes the honest answer is that what it does is
explain.

## What the wiring cost, and one thing worth remembering

`oauth.RequireClientAuth` decides whether *any* authentication method applies
before one is attempted. It could only see secrets in the request body. So it
refused the request before the attestation was ever looked at. The error said
"client authentication is required" to an application that had supplied it.

Its own comment already recorded this happening to `private_key_jwt`, and then
again to [mutual TLS](mutual-tls.md) (Transport Layer Security). ABCA is the
third. The gate now carries the general rule
instead of a third special case. `clients.Client` carries the registered method,
so the gate can see it at all.

## Not implemented

- **DPoP combined mode** (§5.2, §7.3), `attest_jwt_client_auth_dpop`. It is not
  advertised in metadata either. Advertising a method Signari would refuse is the
  same dishonesty as advertising an endpoint that 404s.
- **§6.2 challenges on previous responses.** Signari returns a fresh challenge on
  `use_attestation_challenge`, which is the case §7.4 makes mandatory. Attaching
  one to every successful response is optional, and not done.
- **Resource-server-side attestation** (§7.6, "as an additional security signal").

## Harsh review against draft-10 (August 2026)

Currency was verified at the datatracker first:
**draft-ietf-oauth-attestation-based-client-auth-10, 6 July 2026**, the revision
implemented here.

Every check in §7.1 and §7.2 was read against the code. Then every guarantee was
deleted in turn, to see whether a test noticed.

### Conformance

All twelve §7.1 requirements hold. They are exactly one header, the required
claims, asymmetric algorithms only, and a signature by a trusted attester. They
also include `cnf` not being a private key, freshness, and `client_id` matching
`sub`.

§7.2's rules 1–8 hold likewise. Rule 9 (replay) is implemented in the caller,
through single-use challenges, which the draft leaves conditional on deployment.

### Two tests that passed for the wrong reason

**An untrusted attester.** `TestAnAttestationFromAnUnknownAttesterIsRefused`
asserted only that the call errored. Bypassing the trust check left it passing.
With no key matched, the payload stays nil, and the JSON decode a few lines later
fails, so an error still came back.

The test could not distinguish "no attester vouched for this" from "the bytes did
not parse". It would have gone on passing if the trust check were deleted
outright. It now asserts the reason.

**A future-dated attestation.** This was refused by the code, and tested by
nothing. It is the same shape as the defect found in the Transaction Token
verifier: a timestamp that MOVES the usable window rather than lengthening it. An
attester with a badly wrong clock produces one by accident.

It is now covered, together with the case that must still work. A few seconds of
skew is tolerated, because an attester whose clock is marginally fast must not be
unable to attest anything.

### Three survivors that are not defects

Deleting these breaks no test, and should not:

- **exactly-one-signature**: a compact JSON Web Signature (JWS) carries one by
  construction, so the check is unreachable defence.
- **`cnf.jwk` presence**: an absent value fails the JSON Web Key (JWK) unmarshal
  on the next line.
- **`cnf` key validity**: an unusable key cannot verify the PoP.

Each is caught by an adjacent check, so a mutation to it leaves the system
correct. Treating every surviving mutant as a finding would be as wrong as
ignoring them. What matters is whether the property still holds by some route.

---

## What is implemented, against draft-10 — 24 August 2026

`internal/abca/abca.go` tracks
`draft-ietf-oauth-attestation-based-client-auth-10` (6 July 2026). It was
re-verified against the draft text on this date. Implemented in full:

- The §6.1 **challenge endpoint**, and both header artefacts.
- Every §7.1 check, and §7.2 rules 1–8, including rule 5, refusing a `cnf` that
  carries a private key.
- **Single-use challenges**, swept by the janitor, Signari's clean-up job.
- The three §7.4 error codes (`use_attestation_challenge`,
  `use_fresh_attestation`, `invalid_client_attestation`).
- `client_attestation_pop_methods_supported` in discovery.

The check the whole mechanism rests on is the **challenge match**. Parsing the
`challenge` claim without verifying it against a value Signari issued reduces
attestation to a signed assertion whose inputs the application chose. Replay then
becomes free.

That check, the `jti` replay guard and the `iat` freshness bound are each tested
individually, rather than assumed to follow from the others.
